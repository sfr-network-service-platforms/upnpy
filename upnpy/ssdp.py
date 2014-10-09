
"""ssdp handling"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import http
import time, socket, sys
import logging
import gevent, gevent.pywsgi
import httplib, mimetools

try:
    import cStringIO as StringIO
except:
    import StringIO

EXPIRY = 1800

class SSDPHandler(object):

    def __init__(self, server):
        self.server = server
        self.logger = logging.getLogger('ssdp')        
        
    def __call__(self, env, start_response):

        method = getattr(self, 'do_'+env['REQUEST_METHOD'].replace('-', '_'), None)
        if callable(method):
            return method(env, start_response)
        else:
            self.logger.error("unhandled method %s", env['REQUEST_METHOD'])
            return []
            
    def do_M_SEARCH(self, env, start_response):
        if env.get('HTTP_MAN', None) != '"ssdp:discover"': return []
        st = env.get('HTTP_ST',None)
        #print self.server.address
        for a in self.server.server._advertisement.values():
            if st in ['ssdp:all',
                      a.type,
                      a.usn]:

                #send SSDPEntry headers
                headers=a.headers.copy()
                #append common headers
                headers.update({
                        'ST': a.type,
                        'USN': a.usn,
                        'CACHE-CONTROL':'max-age=%d' % a.expiry,
                        'EXT': ''})
                #modify location headers (host computed at send time)
                for k, secure in {'LOCATION':False, 'SECURELOCATION.UPNP.ORG':True}.items():
                    if k in a.headers:
                        headers[k] = self.server._url(a.headers[k], secure)
                start_response('200 OK', headers.items())
        return []

    def do_NOTIFY(self, env, start_response):
        #print env
        activity = env.get('HTTP_NTS',':').split(':')[1]
        usn = env.get('HTTP_USN',None)
        if activity in ['alive', 'update']:
            expiry = time.time()
            headers = dict()
            for k, v in env.items():
                if k.startswith('HTTP_'):
                    headers[k[5:]] = v
            #self.logger.debug('NOTIFY %s %s', usn, headers['LOCATION'])
            try:
                expiry += int(env.get('HTTP_CACHE_CONTROL', '=%d' % EXPIRY).split('=')[1])
            except:
                expiry += EXPIRY            
            self.server.server.alive(
                usn,
                env.get('HTTP_NT', None),
                headers,
                expiry
                )
        elif activity == 'byebye':
            self.server.server.byebye(usn)
        else:
            self.logger.error("NOTIFY : unhandled NTS %s", activity)

        return []

#object to request new-style for super
class SSDPServer(object):

    PORT = 1900
    MIP = '239.255.255.250'
    MIPv6 = '239.255.255.250'

    def __init__(self, upnpy, *args, **kwargs):

        self.upnpy = upnpy
        self.logger = logging.getLogger('ssdp')        

        self._seen = {}
        import weakref
        self._handlers = weakref.WeakSet()
        self._advertisement = {}
        
        self._iface_servers = []

        if upnpy.server_address:
            self._iface_servers.append(SSDPSingleServer(self, upny.server_address))
            #self._any_server = self._iface_servers[0]
        else:
            import ifaces
            for i, a in ifaces.get_addrs(ifaces.AF_INET):
                #if i == 'lo': continue
                self._iface_servers.append(SSDPSingleServer(self, a))

            #self._any_server = SSDPSingleServer(self, ('0.0.0.0', self.PORT))

        #print map(lambda s:s.address, self._iface_servers)#+[self._any_server])
                           
    def msearch(self, type, mx=5.0):
        responses = self.send_request((self.MIP, self.PORT), 'M-SEARCH', '*',
                                      headers=dict(MAN='"ssdp:discover"',
                                                   MX="%d" % mx,
                                                   ST=type),
                                      timeout=mx)

        for r in responses:
            expiry = time.time()
            try:
                expiry += int(r.getheader('Cache-Control', '=%d' % EXPIRY).split('=')[1])
            except:
                expiry += EXPIRY    
            self.alive(
                r.getheader('USN',None),
                r.getheader('ST', None),
                dict(map(lambda kv: (kv[0].upper(), kv[1]), r.getheaders())),
                expiry
                )

    def send_request(self, to, method, path, headers=None, body=None, timeout=0):
        req = SSDPConnection(to[0], to[1], timeout=timeout)
        #req.set_debuglevel = 9
        req.request(method, path, body, headers)

        return req.getresponses()

    def advertise(self, devser):

        self._advertise(devser, devser.USN, devser._type)

        #for device
        if 'UDN' in devser._ATTRS:
            self._advertise(devser, devser.UDN, devser.UDN)

        #for root
        if not devser._parent:
            self._advertise(devser, "%s::upnp:rootdevice" % devser.UDN, "upnp:rootdevice")

    def _advertise(self, devser, usn, type):

        headers = dict(LOCATION=devser._location)
        if devser._protection:
            headers['SECURELOCATION.UPNP.ORG'] = devser._location

        e = SSDPEntry(usn,
                      type,
                      headers,
                      devser.EXPIRY,
                      None)
        self._notify(e, 'alive')

    def withdraw(self, devser):

        self._withdraw(devser, devser.USN, devser._type)

        #for device
        if 'UDN' in devser._ATTRS:
            self._withdraw(devser, devser.UDN, devser.UDN)

        #for root
        if not devser._parent:
            self._withdraw(devser, "%s::upnp:rootdevice" % devser.UDN, "upnp:rootdevice")

    def _withdraw(self, devser, usn, type):

        headers = dict(LOCATION=devser._location)
        if devser._protection:
            headers['SECURELOCATION.UPNP.ORG'] = devser._location

        e = SSDPEntry(usn,
                      type,
                      headers,
                      devser.EXPIRY,
                      None)

        if (usn, type) not in self._advertisement:
            return

        self._notify(e, 'byebye')
             
    def _notify(self, ssdp, activity):
        
        for s in self._iface_servers:
            s.notify(ssdp, activity)
                   
        key = (ssdp.usn, ssdp.type)

        if activity == 'alive':
            self._advertisement[key] = SSDPEntry(ssdp.usn, ssdp.type, ssdp.headers, ssdp.expiry, gevent.spawn_later(ssdp.expiry/3, self._notify, ssdp, 'alive'))

        elif key in self._advertisement:
            self._advertisement[key].devices.kill()
            del self._advertisement[key]
            
    def alive(self, usn, type, headers, expiry):

        new = usn not in self._seen

        import weakref
        entry = SSDPEntry(usn, type, headers, expiry, 
                          weakref.WeakSet() if new else self._seen[usn].devices)

        #merge and listify locations headers
        for h in ['LOCATION', 'SECURELOCATION.UPNP.ORG']:
            l = set()
            if h in entry.headers:
                l.add(entry.headers[h])
            if usn in self._seen and h in self._seen[usn].headers:
                l |= self._seen[usn].headers[h]
            if l:
                entry.headers[h] = l
       
        self._seen[usn] = entry

        if new:
            for h in self._handlers:
                if h.match(entry):
                    try:
                        h.create(entry)              
                    except Exception, e:
                        self.logger.error('cannot access device %s', e)

        gevent.spawn_later(2*(expiry-time.time()), self._mayexpire, usn)

    def _mayexpire(self, usn):

        if usn in self._seen and self._seen[usn].expiry < time.time():
            self.byebye(usn, True)

    def byebye(self, usn, lost=False):        
        entry = self._seen.pop(usn, None)        
        if entry:
            #self.logger.info("byebye %s%s devices %s", "lost " if timeout else "", usn, entry.devices)
            for d in entry.devices:
                if d._state != "byebye":
                    d._byebye(lost)

    def add_handler(self, handler):

        self._handlers.add(handler)       

        for usn, entry in self._seen.items():
            if handler.match(entry):
                try:
                    handler.create(entry)              
                except Exception, e:
                    self.logger.error('cannot access device %s', e)

    def clean(self):
        for usn in self._seen.keys():
            self.byebye(usn)
        self._handlers = []

    def info(self):
        print "\n".join("%i %s (%s)" % (e.expiry, e.usn, ",".join(e.headers['LOCATION'] | e.headers.get('SECURELOCATION.UPNP.ORG', set()))) for e in sorted(self._seen.values(), key=lambda e:e.usn))

class WSGIHandler(gevent.pywsgi.WSGIHandler):
    protocol_version = 'HTTP/1.1'
    MessageClass = mimetools.Message

    import upnpy
    import sys
    SERVER_HEADER = ('Server', 'Upnpy/%s, UPnP/%s, Python/%s' % (upnpy.__version__, upnpy.UPNP_VERSION, sys.version.split()[0]))

    def __init__(self, data, address, server, rfile=None):
        self.client_address = address
        self.server = server
        self.rfile = StringIO.StringIO(data)
        self.socket = PseudoConnectedSocket(address, server.socket)

    def handle(self):
        try:
            while self.socket is not None:
                self.time_start = time.time()
                self.time_finish = 0
                result = self.handle_one_request()
                if result is None:
                    break
                if result is True:
                    continue
                self.status, response_body = result
                self.socket.sendall(response_body)
                if self.time_finish == 0:
                    self.time_finish = time.time()
                self.log_request()
                break
        finally:
            #if self.socket is not None:
            #    try:
                    # read out request data to prevent error: [Errno 104] Connection reset by peer
            #        try:
            #            self.socket._sock.recv(16384)
            #        finally:
            #            pass
                        #self.socket._sock.close()  # do not rely on garbage collection
                        #self.socket.close()
            #    except socket.error:
            #        pass
            self.__dict__.pop('socket', None)
            self.__dict__.pop('rfile', None)

    def finalize_headers(self):
        super(WSGIHandler, self).finalize_headers()
        self.response_headers.append(self.SERVER_HEADER)

    def log_request(self):
        pass

        
class SSDPSingleServer(gevent.server.DatagramServer, gevent.pywsgi.WSGIServer):

    handler_class = WSGIHandler
    PROTO = socket.SOL_UDP

    def __init__(self, server, if_address, backlog=None, spawn='default', log='default', handler_class=None, environ=None):

        self.server = server
        self.if_address = if_address

        self.environ = dict(SERVER_NAME='ssdp')

        gevent.server.DatagramServer.__init__(self, (server.MIP, server.PORT))

        self.application =  SSDPHandler(self)
        if handler_class is not None:
            self.handler_class = handler_class
        self.log=http.FileLogger('ssdp')
        self.set_environ(environ)
        self.set_max_accept()
        self.start()        

    def init_socket(self):
        gevent.server.DatagramServer.init_socket(self)
        self.join_multicast()
        self.update_environ()

    def join_multicast(self):
        #print "multicast", self.address
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                               socket.inet_aton(self.server.MIP) + socket.inet_aton(self.if_address))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                               socket.inet_aton(self.if_address))

    @property
    def ssl_enabled(self):
        return False

    def notify(self, ssdp, activity):

        #send SSDPEntry headers
        headers = ssdp.headers.copy()
        #append common headers
        headers={'NT': ssdp.type,
                 'USN': ssdp.usn,
                 'NTS': 'ssdp:%s' % activity,
                 'CACHE-CONTROL': 'max-age=%d' % ssdp.expiry}
        #modify location headers (host computed at send time)
        for k, secure in {'LOCATION':False, 'SECURELOCATION.UPNP.ORG':True}.items():
            if k in ssdp.headers:
                headers[k] = self._url(ssdp.headers[k], secure)
        self.send_request((self.server.MIP, self.server.PORT), 'NOTIFY', '*', headers=headers)

    def send_request(self, to, method, path, headers=None, body=None):
        req = SSDPConnection(to[0], to[1], socket=self.socket)
        req.request(method, path, body, headers)
        
    def _url(self, path, secure=False):
        return 'http%s://%s:%d%s' % (
            's' if secure else '',
            self.if_address,
            self.server.upnpy.https.server_port if secure else self.server.upnpy.http.server_port,
            path)

import collections
SSDPEntry = collections.namedtuple('SSDPEntry', 'usn type headers expiry devices')

class PseudoConnectedSocket(object):
    def __init__(self, client, sock):
        self.socket = sock
        self.client = client

    def __getattr__(self, key):
        #print "getattr", key
        return getattr(self.socket, key)

    def makefile(self, mode, bufsize):
        if 'r' in mode:
            return StringIO.StringIO(self.socket.recvfrom(bufsize or 65536)[0])

    def sendall(self, data, flags=None):
        return self.socket.sendto(data, self.client) if flags is None else self.socket.sendto(data, flags, self.client)
    send = sendall
    
    #def close_nop(self):
    #    pass

class SSDPConnection(httplib.HTTPConnection):

    import upnpy
    import sys
    USER_AGENT = ('User-Agent', 'Upnpy/%s, UPnP/%s, Python/%s' % (upnpy.__version__, upnpy.UPNP_VERSION, sys.version.split()[0]))

    def __init__(self, host, port=None, socket=None, strict=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):

        httplib.HTTPConnection.__init__(self, host, port, strict, timeout, source_address)
        if socket:
            self.auto_open = False
            socket = PseudoConnectedSocket((host, port), socket)

        self.sock = socket

        self._create_connection = self._create_pseudo_connection
        
    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
        """Send a request to the server.

        `method' specifies an HTTP request method, e.g. 'GET'.
        `url' specifies the object being requested, e.g. '/index.html'.
        `skip_host' if True does not add automatically a 'Host:' header
        `skip_accept_encoding' if True does not add automatically an
           'Accept-Encoding:' header
        """
        httplib.HTTPConnection.putrequest(self, method, url, skip_host, 1)
        self.putheader(*self.USER_AGENT)

    def getresponses(self, buffering=False):
        "Get the response from the server."

        # if a prior response has been completed, then forget about it.
        if self._HTTPConnection__response and self._HTTPConnection__response.isclosed():
            self._HTTPConnection__response = None

        #
        # if a prior response exists, then it must be completed (otherwise, we
        # cannot read this response's header to determine the connection-close
        # behavior)
        #
        # note: if a prior response existed, but was connection-close, then the
        # socket and response were made independent of this HTTPConnection
        # object since a new request requires that we open a whole new
        # connection
        #
        # this means the prior response had one of two states:
        #   1) will_close: this connection was reset and the prior socket and
        #                  response operate independently
        #   2) persistent: the response was retained and we await its
        #                  isclosed() status to become true.
        #
        if self._HTTPConnection__state != httplib._CS_REQ_SENT or self._HTTPConnection__response:
            raise ResponseNotReady()

        args = (self.sock,)
        kwds = {"strict":self.strict, "method":self._method}
        if self.debuglevel > 0:
            args += (self.debuglevel,)
        if buffering:
            #only add this keyword if non-default, for compatibility with
            #other response_classes.
            kwds["buffering"] = True;

        while True:
            try:
                response = self.response_class(*args, **kwds)
                response.begin()
                yield response
            except socket.timeout:
                self._HTTPConnection__state = httplib._CS_IDLE
                return

        assert response.will_close != httplib._UNKNOWN
        self._HTTPConnection__state = httplib._CS_IDLE

        if response.will_close:
            # this effectively passes the connection to the response
            self.close()
        else:
            # remember this, so we can tell when it is complete
            self._HTTPConnection__response = response

    def _create_pseudo_connection(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        """'Connect' to *address* and return the socket object.

        Convenience function.  Connect to *address* (a 2-tuple ``(host,
        port)``) and return the socket object.  Passing the optional
        *timeout* parameter will set the timeout on the socket instance
        before attempting to connect.  If no *timeout* is supplied, the
        global default timeout setting returned by :func:`getdefaulttimeout`
        is used.  If *source_address* is set it must be a tuple of (host, port)
        for the socket to bind as a source address before making the connection.
        An host of '' or port 0 tells the OS to use the default.
        """

        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                return PseudoConnectedSocket(sa, sock)
            
            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        else:
            raise error("getaddrinfo returns an empty list")
            

    def close(self):
        if self.auto_open:
            httplib.HTTPConnection.close(self)
