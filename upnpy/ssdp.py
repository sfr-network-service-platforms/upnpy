
"""ssdp handling"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import http
import asynchat, asyncore
import time, socket
import logging

from errno import EALREADY, EINPROGRESS, EWOULDBLOCK, ECONNRESET, EINVAL, \
     ENOTCONN, ESHUTDOWN, EINTR, EISCONN, EBADF, ECONNABORTED, EPIPE, EAGAIN, \
     errorcode

#object to request new-style for super
class SSDPServer(object):

    PORT = 1900
    MIP = '239.255.255.250'

    REPLIES = 3

    def __init__(self, upnpy, *args, **kwargs):

        self.upnpy = upnpy

        self._seen = {}
        self._handlers = []
        self._advertisement = {}
        
        self._iface_servers = []

        if upnpy.server_address:
            self._iface_servers.append(SSDPSingleServer(self, upny.server_address))
            self._any_server = self._iface_servers[0]
        else:
            import ifaces
            for i, a in ifaces.get_addrs(ifaces.AF_INET):
                if i == 'lo': continue
                self._iface_servers.append(SSDPSingleServer(self, a, self.PORT))

            self._any_server = SSDPSingleServer(self, '', self.PORT)

        self._emit_server = SSDPSingleServer(self, '0.0.0.0', 0)
                           
    def msearch(self, type, mx=5.0):
        self._emit_server.msearch(type, mx)

    def advertise(self, devser):

        self._advertise(devser, devser._type, devser.USN)

        #for device
        if 'UDN' in devser._ATTRS:
            self._advertise(devser, devser.UDN, devser.UDN)

        #for root
        if not devser._parent:
            self._advertise(devser, "upnp:rootdevice", "%s::upnp:rootdevice" % devser.UDN)

    def _advertise(self, devser, type, usn):

        e = SSDPEntry(usn,
                      type,
                      devser._location,
                      devser._location if devser._protection else None,
                      devser.EXPIRY,
                      None)
        self._notify(e, 'alive')

    def withdraw(self, devser):

        self._withdraw(devser, devser._type, devser.USN)

        #for device
        if 'UDN' in devser._ATTRS:
            self._withdraw(devser, devser.UDN, devser.UDN)

        #for root
        if not devser._parent:
            self._withdraw(devser, "upnp:rootdevice", "%s::upnp:rootdevice" % devser.UDN)

    def _withdraw(self, devser, type, usn):

        e = SSDPEntry(usn,
                      type,
                      devser._location,
                      devser._location if devser._protection else None,
                      devser.EXPIRY,
                      None)
        if e not in self._advertisement:
            return

        self._notify(e, 'byebye')
             
    def _notify(self, ssdp, activity):
        
        for s in self._iface_servers:
            s.notify(ssdp, activity)

            #     self._msend(s, 'NOTIFY', '*', dict({
        #                 'NT' : ssdp.type,
        #                 'USN' : ssdp.usn,
        #                 'NTS' : 'ssdp:%s'%activity,
        #                 'LOCATION' : s._url(ssdp.location),
        #                 'CACHE-CONTROL' : 'max-age=%d' % ssdp.expiry,
        #                 'SERVER':SSDPMessage.version_string()
        #                 }, **({'SECURELOCATION.UPNP.ORG':s._url(ssdp.seclocation, True)} if ssdp.seclocation else {}))
        #                 )
                    
        if activity == 'alive':
            self._advertisement[ssdp] = self.upnpy.set_alarm(lambda:self._notify(ssdp, 'alive'), ssdp.expiry/3)
        elif ssdp in self._advertisement:
            self.upnpy.remove_alarm(self._advertisement[ssdp])
            
    def _periodic(self):
        for a, t in self._advertisement.items():
            if t+a.expiry/2 < time.time():
                self._notify(a, 'alive')

        self._advertisement[ssdp] = time.time()

    # def _msend(self, server, method, path, headers, body=None):
    #     SSDPMessage(method=method,
    #                 path=path,
    #                 headers=headers,
    #                 body=body,
    #                 to=(self.MIP, self.PORT)).dump(server.socket)

    def alive(self, usn, type, location, seclocation, expiry):

        entry = SSDPEntry(usn, type, location, seclocation, expiry,
                          filter(lambda d:d(), self._seen[usn].devices) if usn in self._seen else [])
            
        if usn not in self._seen:
            for h in self._handlers:
                if h.match(entry):
                    h.create(entry)

        self._seen[usn] = entry

    def byebye(self, usn):
        entry = self._seen.pop(usn, None)        
        if entry:
            for d in entry.devices:
                o = d()
                if o:
                    o._byebye()

    def _expire(self):
        now = time.time()

        for usn, entry in self._seen.items():
            if now > entry.expiry: 
                self.byebye(usn)

    def add_handler(self, handler):

        self._expire()

        self._handlers.append(handler)

        for usn, entry in self._seen.items():
            if handler.match(entry):
                handler.create(entry)

    def remove_handler(self, handler):

        self._handlers.remove(handler)

    def clean(self):
        for usn in self._seen.keys():
            self.byebye(usn)
        self._handlers = []

class SSDPRequest(http.HTTPRequest):

    def parse_requestline(self):
        
        rl = self.firstline.split(None, 2) 
        if len(rl) != 3:
            return self.respond(400, "Bad request syntax (%r)" % self.firstline)

        if rl[2].startswith('HTTP/'):
            self.command, self.path, self.request_version = rl
        elif rl[0].startswith('HTTP/'):
            self.request_version, self.command, self.status = rl
        else:
            return self.respond(400, "Bad request syntax (%r)" % self.firstline)

    def adjust_headers(self):
        self.headers.set_if_unset('User-Agent', self.version_string())

    def respond(self, *args, **kwargs):
        http.HTTPRequest.respond(self, *args, **kwargs)
        self.response = None #allow multiple responses for a single request

class SSDPResponse(http.HTTPResponse):

    def adjust_headers(self):
        self.headers.set_if_unset('SERVER', self.version_string())

import collections
SSDPEntry = collections.namedtuple('SSDPEntry', 'usn type location seclocation, expiry, devices')

class SSDPSingleServer(http.LoggedDispatcher,asyncore.dispatcher_with_send):

    def __init__(self, server, address, port, interface=None):

        self.server = server
        self.address = address
        self.interface = interface

        http.LoggedDispatcher.__init__(self)
        asyncore.dispatcher_with_send.__init__(self, map=server.upnpy._map)

        self.out_buffer = []

        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.set_reuse_addr()

        if port:
            #print "bind", (self.server.MIP if address else address, port)
            self.bind((self.server.MIP if address else address, port))
        
        if address != '':
            self.join_multicast()

    def join_multicast(self):
        #print "join_multicast", self.address
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                               socket.inet_aton(self.server.MIP) + socket.inet_aton(self.address))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                               socket.inet_aton(self.address))    
            

    def handle_request(self, request):
        method = getattr(self, 'do_'+request.command.replace('-', '_'), None)
        if callable(method):
            method(request)
        else:
            self.logger.error("unhandled method %s", request.command)
            
    def do_M_SEARCH(self, request):
        if self.address == '': return
        if request.headers.get('MAN', None) != '"ssdp:discover"': return
        st = request.headers.get('ST',None)
        #print self.address
        for a in self.server._advertisement:
            if st in ['ssdp:all',
                      a.type,
                      a.usn]:

                headers={
                        'ST': a.type,
                        'USN': a.usn,
                        'LOCATION': self._url(a.location),
                        'CACHE-CONTROL':'max-age=%d' % a.expiry,
                        'EXT': ''}
                if a.seclocation:
                    headers['SECURELOCATION.UPNP.ORG'] = self._url(a.seclocation, True)
                request.respond(200, headers=headers)

    def do_NOTIFY(self, request):
        activity = request.headers.get('NTS',':').split(':')[1]
        usn = request.headers.get('USN',None)
        if activity in ['alive', 'update']:
            expiry = time.time()
            try:
                expiry += int(request.headers.get('Cache-Control', '=1800').split('=')[1])
            except:
                expiry += 1800            
            self.server.alive(
                usn,
                request.headers.get('NT', None),
                request.headers.get('Location', None),
                request.headers.get('SECURELOCATION.UPNP.ORG', None),
                expiry
                )
        elif activity == 'byebye':
            self.server.byebye(usn)
        else:
            self.logger.error("NOTIFY : unhandled NTS %s", activity)

    def do_200(self, request):
        expiry = time.time()
        try:
            expiry += int(request.headers.get('Cache-Control', '=1800').split('=')[1])
        except:
            expiry += 1800            
        self.server.alive(
            request.headers.get('USN',None),
            request.headers.get('ST', None),
            request.headers.get('Location', None),
            request.headers.get('SECURELOCATION.UPNP.ORG', None),
            expiry
            )

    def notify(self, ssdp, activity):

        headers={'NT': ssdp.type,
                 'USN': ssdp.usn,
                 'NTS': 'ssdp:%s' % activity,
                 'LOCATION': self._url(ssdp.location),
                 'CACHE-CONTROL': 'max-age=%d' % ssdp.expiry}
        if ssdp.seclocation:
            headers['SECURELOCATION.UPNP.ORG'] = self._url(ssdp.seclocation, True)
        
        self.send_request((self.server.MIP, self.server.PORT), 'NOTIFY', '*', headers=headers)

    def msearch(self, type, mx):
        self.send_request((self.server.MIP, self.server.PORT), 'M-SEARCH', '*',
                          headers=dict(MAN='"ssdp:discover"',
                                       MX="%d" % mx,
                                       ST=type))
        #for s in self._iface_servers:
        #    self._msend(s, 'M-SEARCH', '*',
        #                dict(MAN='"ssdp:discover"', MX=int(mx), ST=type))
        #, 'M-SEARCH', '*',
        #            dict(MAN='"ssdp:discover"',
        #                 MX=int(mx),
        #                 ST=type))

    def send_request(self, to, command, path, headers=None, body=None):
        conn = SSDPClientConnection(self, to)
        request = conn.REQUEST_CLASS(
            command=command,
            path=path,
            headers=http.Headers({
                    'HOST':'%s:%d' % to},
                                 **(headers or {})),
            body=body,
            )
        conn.send_request(request)         

    def handle_read(self):
        data, addr = self.recv(4096)
        if data:
            try:
                SSDPServerConnection(self, addr, data)
            except Exception, e:
                from asyncore import compact_traceback
                nil, t, v, tbinfo = compact_traceback()

                self.log_info(
                    'error handling SSDP packet %r (%s:%s %s)' % (
                        data,
                        t,
                        v,
                        tbinfo
                        ),
                    'error'
                    )

    def recv(self, buffer_size):
        try:
            data = self.socket.recvfrom(buffer_size)
            if not data:
                # a closed connection is indicated by signaling
                # a read condition, and having recv() return 0.
                return (None, None)
            else:
                return data
        except socket.error, why:
            # winsock sometimes raises ENOTCONN
            if why.args[0] in asyncore._DISCONNECTED:
                return ''
            else:
                raise 

    def writable(self):
        return self.connected and len(self.out_buffer)

    def send(self, data, to):
        if self.debug:
            self.log_info('sending %s to %s' % (repr(data), repr(to)))
        self.out_buffer.append((data, to))
        self.initiate_send()    
        return len(data)

    def initiate_send(self):
        if len(self.out_buffer):
            self.send_buffered(*self.out_buffer.pop(0))

    def send_buffered(self, data, to):
        try:
            result = self.socket.sendto(data, to)
            return result
        except socket.error, why:
            if why.args[0] == EWOULDBLOCK:
                return 0
            elif why.args[0] in (ECONNRESET, ENOTCONN, ESHUTDOWN, ECONNABORTED):
                self.handle_close()
                return 0
            else:
                raise

    def _url(self, path, secure=False):
        return 'http%s://%s:%d%s' % (
            's' if secure else '',
            self.address,
            self.server.upnpy._https.server_port if secure else self.server.upnpy._http.server_port,
            path)

class _SSDPConnection(http._HTTPConnection):
    
    REQUEST_CLASS = SSDPRequest
    RESPONSE_CLASS = SSDPResponse

    def set_idle_handler(self):
        pass
    
    def recv(self, buffer_size):
        return self._incomming

    def getsockname(self):
        return self.server.socket.getsockname()

    def send(self, data):
        return self.server.send(data, self.remote_address)       

    def add_channel(self, sock, map=None):
        #socket already in map
        pass

    def close(self):
        self.connected = False
        self.accepting = False
        self.connecting = False
        #do not close socket

class SSDPClientConnection(_SSDPConnection, http.HTTPClientConnection):

    def __init__(self, server, remote_address):
        http.HTTPClientConnection.__init__(self, server, None, remote_address)
        self.connected = True

class SSDPServerConnection(_SSDPConnection, http.HTTPServerConnection):

    def __init__(self, server, remote_address, data):
        self._incomming = data
        http.HTTPServerConnection.__init__(self, server, None, remote_address)
        self.connected = True

        #handle incomming data
        self.handle_read()
