
"""http handling"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import asyncore, asynchat
import os, socket, string
import logging
import time
import urlparse

try:
    import cStringIO as StringIO
except:
    import StringIO as StringIO

class LoggedDispatcher():
    def __init__(self, name=None):
        name = name or self.__class__.__name__
        self.logger = logging.getLogger(name)
        
    def log(self, message):
        self.logger.error(message)
    def log_info(self, message, type='info'):
        meth = getattr(self.logger, type) if callable(getattr(logging, type, None)) else self.logger.info
        meth('%s : %s', type, message)

class HTTPServer(LoggedDispatcher, asyncore.dispatcher):
    
    BASE_PORT = 49152

    def __init__(self, upnpy, ssl=False):
        LoggedDispatcher.__init__(self, "HTTPSServer" if ssl else "HTTPServer")
        asyncore.dispatcher.__init__(self, map=upnpy._map)
        self.upnpy = upnpy
        self.ssl = ssl

        self.server_port = self.BASE_PORT
        while True:
            try:
                self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
                self.set_reuse_addr()
                self.bind((self.upnpy.server_address, self.server_port))
                break
            except socket.error, e:
                import errno
                if e.errno != errno.EADDRINUSE:
                    raise
            self.del_channel()
            self.server_port += 1
        if self.ssl:
            import ussl
            self.socket = ussl.ssl_connection(self.socket, 'device')
        self.listen(5)

    def handle_accept(self):
        conn_addr = self.accept()
        if not conn_addr: return

        if self.ssl:
            from ussl import SSLHTTPConnection
            SSLHTTPConnection(self, *conn_addr)
        else:
            HTTPConnection(self, *conn_addr)

    def handle_request(self, request):

        up = urlparse.urlparse(request.path)

        request.path = up.path.split('/')[1:]
        request.query = dict((k, v[0]) for k, v in urlparse.parse_qs(up.query).items())
        
        if request.path[0] == '_notification' and \
                self.upnpy._subscriptions.get(request.headers.get('SID', None), lambda:None)():
            ret = self.upnpy._subscriptions.get(request.headers['SID'])().notify(request)
        elif request.path[0] in self.upnpy.devices and len(request.path)>1:
            dev = request.path.pop(0)
            request.base = base='/%s/' % dev
            ret = self.upnpy.devices[dev]._dispatch(request)

        else:            
            return request.send_error(404)

        code = ret[0]
        if code == 0: #response already done by handler
            return

        body = ret[1] if len(ret)>1 else None
        headers = Headers(ret[2] if len(ret)>2 else {})

        request.send_response(code,
                              headers = headers,
                              body = body)

import BaseHTTPServer

class HTTPMessage(object):

    from upnpy import __version__
    import sys

    server_version = "Upnpy/" + str(__version__)
    sys_version = "Python/" + sys.version.split()[0]    

    def __init__(self, connection, firstline=None, response=False):
        self.connection = connection

        self.logger = logging.getLogger(self.__class__.__name__)
        self.access_logger = logging.getLogger('http.access')

        self.request_version = "HTTP/1.1"
        self.command = ""

        self.headers = Headers()
        self.body = None

        self.firstline = firstline

        if firstline:
            if response:
                self.parse_responseline()
            else:
                self.parse_requestline()

    def parse_requestline(self):

        rl = self.firstline.split() 
        if len(rl) == 3:
            self.request_version = rl[2]
            if self.request_version not in ['HTTP/0.9', 'HTTP/1.0', 'HTTP/1.1']:
                return self.send_error(400, "Bad request version (%r)" % self.request_version)
        elif len(rl) == 2:
            self.request_version = "HTTP/0.9"
        else:
            return self.send_error(400, "Bad request syntax (%r)" % self.firstline)

        self.command, self.path = rl[0:2]

    def parse_responseline(self):

        rl = self.firstline.split(None, 2)
        if len(rl) != 3:
            raise Exception("invalid response '%r'" % self.firstline)
        try:
            int(rl[1])
        except ValueError:
            raise Exception("invalid response code '%s'" % self.rl[1])
                    
        self.request_version, self.code, self.status = rl            

    def send_error(self, code, message=None):
        """Send and log an error reply.

        Arguments are the error code, and a detailed message.
        The detailed message defaults to the short entry matching the
        response code.

        This sends an error response (so it must be called before any
        output has been generated), logs the error, and finally sends
        a piece of HTML explaining the error to the user.

        """

        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        self.logger.info('error %d handling request %s (%r, %s)', code, self.firstline, self.headers, self.body[:500] if self.body else None)
        self.log_error("code %d, message %s", code, message)
        # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
        content = (self.error_message_format %
                   {'code': code, 'message': _quote_html(message), 'explain': explain})
        self.send_response(code, message,
                           headers={"Content-Type":self.error_content_type},
                           body=content)

    def send_response(self, code, message=None, headers=None, body=None):
        self.send_responseline(code, message)
        headers = Headers(dict(
               Server=self.version_string(),
               Date=self.date_time_string(),
               Connection=self.headers.get('Connection', 'close')),
                          **(headers or {}))
        headers, body = self.adjust_content(headers, body)
        self.send_headers(headers, body)
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.send_body(body)
        if headers.get('Connection', 'close').lower() != 'keep-alive':
            self.connection.close_when_done()

    def send_responseline(self, code, message=None):
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.send("%s %d %s\r\n" %
                      (self.request_version, code, message))
            # print (self.protocol_version, code, message)

    def send_requestline(self, command, path, version=None):
        """Send the response header and log the response code.

        Also send two standard headers with the server software
        version and the current date.

        """
        self.send("%s %s %s\r\n" %
                      (command, path, version or self.request_version))

    def adjust_content(self, headers=None, body=None):        
        if isinstance(body, unicode):
            body = body.encode('utf-8')
            if 'charset' not in headers.get('Content-Type',''):
                headers['Content-Type'] = ";".join([headers['Content-Type'], 'charset="utf-8"'])
        elif body is None:
            pass

        elif hasattr(body, '__iter__'):
            if 'Content-Length' not in headers:
                if self.request_version != 'HTTP/1.1':
                    body = "".join(body)
                else:
                    headers['Transfer-Encoding'] = 'chunked'
                    body = self.chunked(body)
        else:
            body = str(body)

        if isinstance(body, str) and 'Content-Length' not in headers:
            headers['Content-Length'] = len(body)
    
        return headers, body

    def chunked(self, body):
        while True:
            data = next(body)
            yield "%x\r\n%s\r\n" % (len(data), data)
            if not data:
                break     

    def send_headers(self, headers, body=None):
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()

    def send_header(self, keyword, value):
        """Send a MIME header."""
        if self.request_version != 'HTTP/0.9':
            self.send("%s: %s\r\n" % (keyword, value))

    def end_headers(self):
        """Send the blank line ending the MIME headers."""
        if self.request_version != 'HTTP/0.9':
            self.send("\r\n")
        self.push()

    def send_body(self, body):
        if body is not None:
            self.send(body)

        if isinstance(body, str):
            self.push()

    def send(self, data):
        if hasattr(data, '__iter__'):
            self.connection.push_with_producer(data)
        else:
            self.connection.push(data)

    def push(self):
        self.connection.initiate_send()

    def log_error(self, format, *args):
        self.log_message(format, args, logger=self.logger, level=logging.ERROR)

    def log_request(self, code='-', size='-'):
        self.log_message('"%s" %s %s', (self.firstline, str(code), str(size)),
                         logger=self.access_logger, level=logging.INFO)
    
    def log_message(self, format, args, logger=None, level=None):

        logger = logger or self.logger
        level = level or logging.INFO

        logger.log(level, "%s %s - - [%s] %s",
                   ":".join(map(str, self.connection.getsockname())),
                   self.connection.remote_address[0],
                   self.log_date_time_string(),
                   format%args)

    def log_date_time_string(self):
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
                day, self.monthname[month], year, hh, mm, ss)
        return s

    def version_string(self):
        """Return the server software version string."""
        return self.server_version + ', ' + self.sys_version
                           
    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    def __str__(self):
        return self.firstline or ('%s from %s to %s' % (self.connection.MESSAGE_CLASS.__name__, self.connection.getsockname(), self.connection.remote_address))

    weekdayname = BaseHTTPServer.BaseHTTPRequestHandler.weekdayname
    monthname = BaseHTTPServer.BaseHTTPRequestHandler.monthname

    error_message_format = BaseHTTPServer.DEFAULT_ERROR_MESSAGE
    error_content_type = BaseHTTPServer.DEFAULT_ERROR_CONTENT_TYPE

    responses = BaseHTTPServer.BaseHTTPRequestHandler.responses

_quote_html = BaseHTTPServer._quote_html

def terminator(term=None):
    def terminator_handler(fct):
        fct.terminator = term
        return fct
    return terminator_handler

class HTTPConnection(LoggedDispatcher,asynchat.async_chat):

    MESSAGE_CLASS = HTTPMessage
    KEEP_ALIVE = 10

    def __init__(self, server, sock, remote_address, client=False):
        self.server = server
        self.remote_address = remote_address
        self.client = client

        asynchat.async_chat.__init__(self, sock, map=server._map)
        LoggedDispatcher.__init__(self, self.__class__.__name__+'.%s:%d'%(sock.getsockname() if sock else remote_address))

        self.set_next_handler(self.found_message)

        if client:
            self.callback = None

        self.message = None
        self.data = ""
        self.shutdown = 0

        self.keep_alive = self.KEEP_ALIVE
        self.last_activity = time.time()
        self.set_idle_handler()

    def set_idle_handler(self):

        import weakref
        ref = weakref.ref(self)
        u = self.server if self.client else self.server.upnpy
        def idle_handler():
            c = ref()
            if not c:
                u.remove_idle(me)
                return
            c.idle()
        self.idle_handle = idle_handler.func_globals['me'] = idle_handler

        u.set_idle(idle_handler)

    def idle(self):
        if time.time() > self.last_activity + self.keep_alive:
            self.handle_close()
            u = self.server if self.client else self.server.upnpy
            u.remove_idle(self.idle_handle)

    def create_socket(self):
        asynchat.async_chat.create_socket(self, socket.AF_INET, socket.SOCK_STREAM)

    def create_message(self, *args, **kwargs):
        return self.MESSAGE_CLASS(self, *args, **kwargs)

    def send_request(self, url, command, callback, headers=None, body=None):
        self.logger.debug('send_request %s %s', command, url)

        self.message = None
        request = self.create_message()
        up = urlparse.urlparse(url)

        self.callback = callback

        request.send_requestline(command, urlparse.urlunparse((None, None)+up[2:]))
        headers = Headers({
                'User-Agent':request.version_string(),
                'Connection':'Keep-Alive',
                'Host':up.netloc},
                          **(headers or {}))
        headers, body = request.adjust_content(headers, body)
        request.send_headers(headers, body)
        request.send_body(body)

    def collect_incoming_data(self, data):
        self.data = self.data + data

    def set_next_handler(self, handler, terminator = None):
        
        #if isinstance(self, SSLHTTPConnection):
        #    self.logger.info("set_next_handler '%s' '%s'", self.found_terminator, self.data)

        self.data = ""
        self.found_terminator = handler
        self.set_terminator(terminator or handler.terminator)

    @terminator("\r\n")
    def found_message(self):
        try:
            self._message = self.create_message(self.data, response=self.client)
        except ValueError: #no 3 values to unpack
            self.handle_close()
        self.set_next_handler(self.found_header)

    @terminator("\r\n")
    def found_header(self):
        #if isinstance(self, SSLHTTPConnection):
        #    self.logger.error('found_header %s', self.data)
        headers = self._message.headers
        #print "found_header '%s'" % self.data
        if self.data != '':
            name, value = self.data.split(':', 1)
            headers[name] = value.strip()
            self.set_next_handler(self.found_header)
        else: #last header
            if self._message.body is not None: #last trailer
                self.handle_message()

            elif int(headers.get('Content-Length', '0')) > 0:
                self.set_next_handler(self.found_body, int(headers['Content-Length']))

            elif headers.get('Transfer-Encoding', None) == 'chunked':
                self._message.body = ""
                self.set_next_handler(self.found_chunk_size)

            else:
                self.handle_message()                       

    @terminator()
    def found_body(self):

        self._message.body = self.data
        self.handle_message()
    
    @terminator('\r\n')
    def found_chunk_size(self):
        size = int(self.data.split(';')[0], 16)
        if size:
            self.set_next_handler(self.found_chunk_data, size)
        else:
            #trailers
            self.set_next_handler(self.found_header)

    @terminator()
    def found_chunk_data(self):
        self._message.body += self.data
        self.set_next_handler(self.found_chunk_end)

    @terminator("\r\n")
    def found_chunk_end(self):
        self.set_next_handler(self.found_chunk_size)

    def handle_message(self):        
        self.data = ""
        message = self._message
        del self._message

        self.set_next_handler(self.found_message, '\r\n')

        if self.client:
            if message.headers.get('Connection', 'close').lower() != 'keep-alive':
                self.handle_close()

            if self.callback:
                cb, self.callback = self.callback, None
                try:
                    cb(message)
                except Exception, e:
                    self.logger.exception("handle_request failed")
            else:
                self.message = message
        else:
            try:
                self.server.handle_request(message)
            except Exception, e:
                message.send_error(500)
                self.logger.exception("handle_request failed")
            #    raise

        ##if not self.client:
        #   if message.headers.get('Connection', 'close').lower() == 'keep-alive':
        #        self.set_next_handler(self.found_message, '\r\n')
        #    else:
        #        self.close()

    def push (self, data):
        sabs = self.ac_out_buffer_size
        if len(data) > sabs:
            for i in xrange(0, len(data), sabs):
                self.producer_fifo.append(data[i:i+sabs])
        else:
            self.producer_fifo.append(data)

    def initiate_send(self):
        obs = self.ac_out_buffer_size
        buf = ""
        while self.producer_fifo and self.connected and len(buf)<obs:
            first = self.producer_fifo[0]
            
            if first is None:
                if not self.client and self.connected:
                    self.handle_close()
                return

            elif hasattr(first, '__iter__'):
                try:
                    n = next(first)
                except TypeError, e:
                    self.logger.error("%r %s", first, e)
                buf += n
                if not n:
                    del self.producer_fifo[0]

            else:
                buf += first
                del self.producer_fifo[0]

        if not len(buf):
            return       

        try:
            sent = self.send(buf)

        except socket.error:
            self.handle_error()
            return

        buf = buf[max(sent,0):]
        if len(buf):
            self.producer_fifo.appendleft(buf)        

    def getsockname(self):
        return self.socket.getsockname()

    def handle_connect(self):
        pass

    def handle_read_event(self):
        self.last_activity = time.time()
        try:
            asynchat.async_chat.handle_read_event(self)
        except socket.error, e:
            if self.client:
                self.message = self.MESSAGE_CLASS(self,
                                                  firstline="HTTP/1.0 %d %s"  % (-e.args[0], str(e)),
                                                  response=True)
                if self.callback:
                    self.callback(self.message)

    def handle_write_event(self):
        self.last_activity = time.time()
        asynchat.async_chat.handle_write_event(self)

class ConnectionManager(object):

    def __init__(self, upnpy):
        self.upnpy = upnpy
        self.connections = dict()
        self.pending = dict()

    def send_request(self, url, command, callback, headers, body, on_connect=None):
        #logging.error("send_request %s %s %r %r", url, command, callback, headers)

        up = urlparse.urlparse(url)

        if up.scheme == 'http':
            addr = (up.hostname, up.port or 80, HTTPConnection)
        
        elif up.scheme == 'https':
            from ussl import SSLHTTPConnection
            addr = (up.hostname, up.port or 443, SSLHTTPConnection)
        
        if not addr in self.pending:
            self.pending[addr] = []

        self.pending[addr].append((url, command, callback, headers, body, on_connect))

        self.send_next(addr)

    def reconnect(self, addr):

        cls = addr[2]
        netloc = addr[:2]

        conn = cls(self.upnpy, None, netloc, client=True)
        conn.create_socket()

        if hasattr(conn, 'reuse_session') and addr in self.connections:
            conn.reuse_session(self.connections[addr])
            
        conn.connect(addr[:2])

        self.connections[addr] = conn

    def send_next(self, addr):

        if not addr in self.connections \
                or (not self.connections[addr].connected \
                        and not self.connections[addr].connecting):
            logging.debug('reconnect %r %r', addr, self.connections.get(addr, None))
            self.reconnect(addr)

        conn = self.connections[addr]
        if conn.callback or not self.pending[addr]:
            return

        url, command, callback, headers, body, on_connect = self.pending[addr].pop(0)

        if on_connect:
            on_connect(conn)

        cb=None
        if callback:
            def cb(response):
                #logging.error("cb %s", url)
                self.send_next(addr)
                callback(response)

        #logging.error("conn send_request %s %s %s %r %r", conn, url, command, callback, headers)
        conn.send_request(url, command, cb, headers, body)

        if not callback:
            start = time.time()
            self.upnp.serve_while(lambda:time.time()<start+10.0 and not conn.message)
            self.send_next(addr)
            return conn.message

    def clean(self):
        for n, c in self.connections.items():
            c.handle_close()
            del self.connections[n]
    

from UserDict import IterableUserDict
class Headers(IterableUserDict):

    def __getitem__(self, key):
        for k, v in self.data.items():
            if k.lower() == key.lower():
                return v
        else:
            raise KeyError(key)

    def __contains__(self, key):
        return key.lower() in map(lambda s:s.lower(), self.data.keys())

    def __setitem__(self, key, value):
        for k in self.data.keys():
            if k.lower() == key.lower():
                self.data[k] = value
        else:
            self.data[key] = value
    
def main():
    import upnpy
    u = upnpy.Upnpy()
    s = HTTPServer(u, ssl=False)
    asyncore.loop(map=u._map)
    
if __name__ == '__main__':
    main()
