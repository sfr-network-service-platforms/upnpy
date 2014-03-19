
"""http handling"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import asyncore, asynchat
import os, socket
import logging
import time
import urlparse

class LoggedDispatcher(object):
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
        try:
            conn_addr = self.accept()
        except Exception, e:
            self.logger.warning("handle_accept : %s", e)
            return
        if not conn_addr: return

        if self.ssl:
            from ussl import SSLHTTPServerConnection
            SSLHTTPServerConnection(self, *conn_addr)
        else:
            HTTPServerConnection(self, *conn_addr)
        
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
            return request.respond(404)

        code = ret[0]
        if code == 0: #response already done by handler
            return

        body = ret[1] if len(ret)>1 else None
        headers = Headers(ret[2] if len(ret)>2 else {})

        request.respond(code,
                        headers = headers,
                        body = body)

class Control(object):
    pass

Wait = Control()
Close = Control()

import BaseHTTPServer
class _HTTPMessage(object):

    from upnpy import __version__
    import sys

    server_version = "Upnpy/" + str(__version__)
    sys_version = "Python/" + sys.version.split()[0]    

    def __init__(self, firstline=None, headers=None, body=None, http_version=None, on_connect=None):

        self.logger = logging.getLogger(self.__class__.__name__)
        self.access_logger = logging.getLogger("http.access")

        self.http_version = http_version or "HTTP/1.1"

        self.firstline = firstline
        self.headers = Headers(headers or {})
        self.body = body

        self.connection = None
        self._generator = None
        self._discard_body = False
        self.sent = False
        self.on_connect = on_connect

    def next(self, connection):
        if not self._generator:
            self._generator = iter(self)
            self.connection = connection
            if callable(self.on_connect):
                self.on_connect(self)

        return next(self._generator)

    def __iter__(self):
        self.adjust_headers()
        self.adjust_content()

        yield "%s\r\n" % self.firstline
        for k, v in self.headers.items():
            yield "%s: %s\r\n" % (k, v)
        yield "\r\n"
        if self._discard_body:
            return
        elif isinstance(self.body, str):
            yield self.body
        elif hasattr(self.body, '__iter__'):
            while True:
                try:
                    yield next(self.body)
                except StopIteration:
                    break

    # def send_response(self, code, status=None, headers=None, body=None):
    #     self.send_responseline(code, status)
    #     headers = Headers(dict(
    #            Server=self.version_string(),
    #            Date=self.date_time_string(),
    #            Connection=self.headers.get('Connection', 'close')),
    #                       **(headers or {}))
    #     headers, body = self.adjust_content(headers, body)
    #     self.send_headers(headers, body)
    #     if self.method != 'HEAD' and code >= 200 and code not in (204, 304):
    #         self.send_body(body)
    #     if headers.get('Connection', 'close').lower() != 'keep-alive':
    #         self.connection.close_when_done()

    # def send_responseline(self, code, status=None):
    #     self.log_request(code)
    #     if status is None:
    #         if code in self.responses:
    #             status = self.responses[code][0]
    #         else:
    #             status = ''
    #     if self.http_version != 'HTTP/0.9':
    #         self.send("%s %d %s\r\n" %
    #                   (self.http_version, code, status))
    #         # print (self.protocol_version, code, status)

    # def send_requestline(self, method, path, http_version=None):
    #     """Send the response header and log the response code.

    #     Also send two standard headers with the server software
    #     version and the current date.

    #     """
    #     self.send("%s %s %s\r\n" %
    #                   (method, path, version or self.http_version))

    def adjust_content(self):
        
        if isinstance(self.body, unicode):
            self.body = self.body.encode('utf-8')
            if 'charset' not in self.headers.get('Content-Type',''):
                self.headers['Content-Type'] = ";".join([self.headers['Content-Type'], 'charset="utf-8"'])
        elif self.body is None:
            pass

        elif hasattr(self.body, '__iter__'):
            if 'Content-Length' not in self.headers:
                if self.http_version != 'HTTP/1.1':
                    self.body = "".join(self.body)
                else:
                    self.headers['Transfer-Encoding'] = 'chunked'
                    self.body = self._chunked(self.body)
        else:
            self.body = str(self.body)

        if isinstance(self.body, str) and 'Content-Length' not in self.headers:
            self.headers['Content-Length'] = len(self.body)

    def _chunked(self, body):
        while True:
            data = next(body)
            yield "%x\r\n%s\r\n" % (len(data), data)
            if not data:
                break     

    # def send_headers(self, headers, body=None):
    #     for k, v in headers.items():
    #         self.send_header(k, v)
    #     self.end_headers()

    # def send_header(self, keyword, value):
    #     """Send a MIME header."""
    #     if self.http_version != 'HTTP/0.9':
    #         self.send("%s: %s\r\n" % (keyword, value))

    # def end_headers(self):
    #     """Send the blank line ending the MIME headers."""
    #     if self.http_version != 'HTTP/0.9':
    #         self.send("\r\n")
    #     self.push()

    # def send_body(self, body):
    #     if body is not None:
    #         self.send(body)

    #     if isinstance(body, str):
    #         self.push()

    # def send(self, data):
    #     if hasattr(data, '__iter__'):
    #         self.connection.push_with_producer(data)
    #     else:
    #         self.connection.push(data)

    # def push(self):
    #     self.connection.initiate_send()

    # def log_error(self, format, *args):
    #     self.log_message(format, args, logger=self.logger, level=logging.ERROR)

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
        return "%s, UPnP/1.1, %s" % (self.server_version, self.sys_version)
                           
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
        return "<%s %s>" % (self.__class__.__name__, self.firstline)

    weekdayname = BaseHTTPServer.BaseHTTPRequestHandler.weekdayname
    monthname = BaseHTTPServer.BaseHTTPRequestHandler.monthname

    error_message_format = BaseHTTPServer.DEFAULT_ERROR_MESSAGE
    error_content_type = BaseHTTPServer.DEFAULT_ERROR_CONTENT_TYPE

    RESPONSES = BaseHTTPServer.BaseHTTPRequestHandler.responses

_quote_html = BaseHTTPServer._quote_html


class HTTPRequest(_HTTPMessage):

    RETRY = 3

    def __init__(self, method=None, path=None, *args, **kwargs):

        self.callback = None
        self.response = None
        self._retries = 0

        _HTTPMessage.__init__(self, *args, **kwargs)

        if method and path:
            self.method = method
            self.path = path
            self.firstline = "%s %s %s"  % (method, path, self.http_version)
        elif self.firstline:
            self.parse_requestline()
        else:
            raise ValueError("neither firstline nor (method,path) set!")

    def parse_requestline(self):

        rl = self.firstline.split() 
        if len(rl) == 3:
            self.http_version = rl[2]
            if self.http_version not in ['HTTP/0.9', 'HTTP/1.0', 'HTTP/1.1']:
                self.respond(400, "Bad request version (%r)" % self.http_version)
        elif len(rl) == 2:
            self.http_version = "HTTP/0.9"
        else:
            self.respond(400, "Bad request syntax (%r)" % self.firstline)

        self.method, self.path = rl[0:2]

    def adjust_headers(self):
        self.headers.set_if_unset('User-Agent', self.version_string())
        self.headers.set_if_unset('Connection', 'Keep-Alive')

    def respond(self, code, status=None, headers=None, body=None):

        if self.response:
            raise Exception('response already set!')

        self.log_request(code)
        
        self.response = HTTPResponse(code=code, status=status, http_version=self.http_version,
                            headers = Headers(headers,
                                              Connection=self.headers.get('Connection', 'Keep-Alive')),
                            body = body)

        if self.method == 'HEAD' or code < 100 or code in (204, 304):
            self.response._discard_body = True

        self.connection.handle_write_event()
        #self.connection.initiate_send()

        return False
    
    def handle_response(self, response):
        self.response = response
        if callable(self.callback):
            self.callback(response)

    def prepare_retry(self):
        self.sent = False
        self.response = None
        self._generator = None
        self._retries += 1

class HTTPResponse(_HTTPMessage):

    def __init__(self, code=None, status=None, *args, **kwargs):
        _HTTPMessage.__init__(self, *args, **kwargs)
        if code is not None:
            self.code = code
            self.status = status or self.RESPONSES.get(code, '???')[0]
            self.firstline = "%s %s %s"  % (self.http_version, code, self.status)
        elif self.firstline:
            self.parse_responseline()
        else:
            raise ValueError("neither firstline nor code set!")

    @classmethod
    def from_exception(cls, exception):
        if isinstance(exception, socket.error):
            return cls(-exception.args[0], exception.args[1])
        else:
            return cls(0, str(exception))        

    def parse_responseline(self):

        rl = self.firstline.split(None, 2)
        if len(rl) != 3:
            raise Exception("invalid response '%r'" % self.firstline)
        try:
            int(rl[1])
        except ValueError:
            raise Exception("invalid response code '%s'" % self.rl[1])
                    
        self.http_version, self.code, self.status = rl            

    def adjust_headers(self):
        self.headers.set_if_unset('Server', self.version_string())
        self.headers.set_if_unset('Date', self.date_time_string())
        self.headers.set_if_unset('Connection', 'Keep-Alive')

def terminator(term=None):
    def terminator_handler(fct):
        fct.terminator = term
        return fct
    return terminator_handler

class _HTTPConnection(LoggedDispatcher,asynchat.async_chat):

    KEEP_ALIVE = 10
    REQUEST_CLASS = HTTPRequest
    RESPONSE_CLASS = HTTPResponse

    def __init__(self, server, sock, remote_address):
        self.server = server
        self.remote_address = remote_address

        asynchat.async_chat.__init__(self, sock, map=server._map)
        LoggedDispatcher.__init__(self, self.__class__.__name__+'.%s:%d'%(sock.getsockname() if sock else remote_address))

        self.message = None
        self.pipeline = []
        self.pipelining = False
        self.read_data = ""
        self.write_data = ""

        self.keep_alive = self.KEEP_ALIVE
        self.last_activity = time.time()
        self.set_idle_handler()

    def idle(self):
        if time.time() > self.last_activity + self.keep_alive:
            self.logger.debug('closing idle connection')
            self.handle_close()

    def create_socket(self):
        asynchat.async_chat.create_socket(self, socket.AF_INET, socket.SOCK_STREAM)

    def collect_incoming_data(self, data):
        self.read_data = self.read_data + data

    def set_next_handler(self, handler, terminator = None):
        
        #if self.__class__.__name__ == 'SSLHTTPConnection':
        #self.logger.debug("set_next_handler '%s' '%s'", self.found_terminator, self.read_data)
        
        self.read_data = ""
        self.found_terminator = handler
        self.set_terminator(terminator or handler.terminator)

    @terminator("\r\n")
    def found_request(self):
        try:
            self.message = self.REQUEST_CLASS(firstline = self.read_data)
            self.message.connection = self
            self.pipeline.append(self.message)
            self.set_next_handler(self.found_header)
        except ValueError: #no 3 values to unpack
            self.handle_close()

    @terminator("\r\n")
    def found_response(self):
        try:
            self.message = self.RESPONSE_CLASS(firstline=self.read_data)
            self.message.connection = self
            self.set_next_handler(self.found_header)
        except ValueError: #no 3 values to unpack
            self.handle_close()

    @terminator("\r\n")
    def found_header(self):
        headers = self.message.headers
        if self.read_data != '':
            name, value = self.read_data.split(':', 1)
            headers[name.strip()] = value.strip()
            self.set_next_handler(self.found_header)
        else: #last header
            if self.message.body is not None: #last trailer
                self.handle_message()

            elif int(headers.get('Content-Length', '0')) > 0:
                self.set_next_handler(self.found_body, int(headers['Content-Length']))

            elif headers.get('Transfer-Encoding', None) == 'chunked':
                self.message.body = ""
                self.set_next_handler(self.found_chunk_size)

            else:
                self.handle_message()                       

    @terminator()
    def found_body(self):
        self.message.body = self.read_data
        self.handle_message()
    
    @terminator('\r\n')
    def found_chunk_size(self):
        size = int(self.read_data.split(';')[0], 16)
        if size:
            self.set_next_handler(self.found_chunk_data, size)
        else:
            #trailers
            self.set_next_handler(self.found_header)

    @terminator()
    def found_chunk_data(self):
        self.message.body += self.read_data
        self.set_next_handler(self.found_chunk_end)

    @terminator("\r\n")
    def found_chunk_end(self):
        self.set_next_handler(self.found_chunk_size)

    def getsockname(self):
        return self.socket.getsockname()

    def handle_connect(self):
        pass

    def handle_read_event(self):
        self.last_activity = time.time()
        asynchat.async_chat.handle_read_event(self)

    def handle_write_event(self):
        self.last_activity = time.time()
        asynchat.async_chat.handle_write_event(self)

class HTTPClientConnection(_HTTPConnection):

    def __init__(self, *args, **kwargs):
        _HTTPConnection.__init__(self, *args, **kwargs)
        self.set_next_handler(self.found_response)

    def set_idle_handler(self):

        upnpy = self.server
        self._idle_handle = upnpy.set_idle(_IdleHandler(upnpy, self))

    def reconnect(self):
        conn = self.__class__(self.server, None, self.remote_address)
        conn.create_socket()
        return conn

    def send_request(self, request):
        self.pipeline.append(request)
        #self.logger.info('send_request %s on %s (%s)', request, self, self.pipeline)
        #self.handle_write_event()
        self.initiate_send()
    
    def handle_message(self):
        response = self.message
        self.message = None

        #self.logger.info('receive response %s on %s', response, self)
        request = self.pipeline.pop(0)

        if response.headers.get('Connection',
                                "close" if response.http_version is "HTTP/1.0" else "keep-alive")\
                           .lower() == 'close':
            self.handle_close()
        else:
            self.set_next_handler(self.found_response)
            self.pipelining = True

        request.handle_response(response)

    def initiate_send(self):
        obs = self.ac_out_buffer_size
       
        close = False

        iterpipe = self.pipeline       
        notsent = filter(lambda request:request.sent==False, self.pipeline)

        while self.connected and len(self.write_data) < obs and notsent:

            try:
                n = notsent[0].next(self)
            except StopIteration:
                notsent[0].sent = True
                break

            if n == Wait:
                break
            elif n == Close:
                close = True
                break
            else:
                self.write_data += n                 

        if not self.write_data:
            return

        try:
            sent = self.send(self.write_data)
            self.write_data = self.write_data[max(sent,0):]
        except socket.error:
            self.handle_error()
            return
        
        if close:
            self.handle_close()

    def writable(self):
        return self.write_data \
            or any(map(lambda request:request.sent==False, self.pipeline))

    def handle_close(self):
        _HTTPConnection.handle_close(self)
        if hasattr(self, '_idle_handle'):
            upnpy = self.server
            upnpy.remove_idle(self._idle_handle)
        while self.pipeline:
            self.pipeline.pop().handle_response(self.RESPONSE_CLASS(0, 'connection closed'))

    # def handle_error():
    #     import sys
    #     ex = sys.exc_info()[1]
    #     logging.error("from_exception : %s", ex)
    #     while self.pipeline:
    #         self.pipeline.pop().handle_response(self.RESPONSE_CLASS.from_exception(ex))
    #     _HTTPConnection.handle_error(self)

class HTTPServerConnection(_HTTPConnection):

    def __init__(self, *args, **kwargs):
        _HTTPConnection.__init__(self, *args, **kwargs)
        self.set_next_handler(self.found_request)

    def set_idle_handler(self):

        upnpy = self.server.upnpy
        self._idle_handle = upnpy.set_idle(_IdleHandler(upnpy, self))

    def handle_message(self):        
        message = self.message
        self.message = None

        self.set_next_handler(self.found_request)

        try:
            self.server.handle_request(message)
        except Exception, e:
            self.logger.exception("handle_request failed")
            message.respond(500)

    def initiate_send(self):
        obs = self.ac_out_buffer_size
       
        close = False
        response = self.pipeline[0].response if self.pipeline else None
        
        while self.connected and len(self.write_data) < obs and getattr(response, 'sent', True) == False:

            try:
                n = response.next(self)
            except StopIteration:
                self.pipeline.pop(0)
                break

            if n == Wait:
                break
            elif n == Close:
                close = True
                break
            else:
                self.write_data += n                 

        if not self.write_data:
            return

        try:
            sent = self.send(self.write_data)
            self.write_data = self.write_data[max(sent,0):]                    
        except socket.error:
            self.handle_error()
            return
        
        if close:
            self.handle_close()

    def writable(self):
        return self.write_data \
            or (self.pipeline and getattr(self.pipeline[0].response, 'sent', True) == False)

    def handle_close(self):
        if hasattr(self, '_idle_handle'):
            upnpy = self.server.upnpy
            upnpy.remove_idle(self._idle_handle)
        _HTTPConnection.handle_close(self)

class _IdleHandler(object):
    def __init__(self, upnpy, connection):
        import weakref
        self.upnpy = upnpy
        self.connection = weakref.ref(connection)

    def __call__(self):
        c = self.connection()
        if c:
            c.idle()
        else:
            self.upnpy.remove_idle(self)                    

class ConnectionManager(object):

    def __init__(self, upnpy):
        self.upnpy = upnpy
        self.connections = dict()
        self.pending = dict()

    def create_request(self, url, method, callback=None, headers=None, body=None, **kwargs):

        up = urlparse.urlparse(url)

        if up.scheme == 'http':
            addr = (up.hostname, up.port or 80, HTTPClientConnection)
        
        elif up.scheme == 'https':
            from ussl import SSLHTTPClientConnection
            addr = (up.hostname, up.port or 443, SSLHTTPClientConnection)
                    
        request = addr[2].REQUEST_CLASS(method=method,
                                        path=urlparse.urlunparse((None, None)+up[2:]),
                                        headers=Headers(Host=up.netloc, **(headers or {})),
                                        body=body,
                                        **kwargs)
        request._addr = addr
        request._callback = callback

        def cb(response):
            if response.code <= 0 and request._retries < 3:
                request.logger.warning('retry failed request on %s:%s%s', request._addr[0], request._addr[1], request.path)
                request.prepare_retry()
                self.pending[addr].insert(0, request)
                self.send_next(addr)
            else:
                self.send_next(addr)
                if callable(request._callback):
                    request._callback(response)

        request.callback = cb

        return request

    def send(self, request):
        addr = request._addr
        if not addr in self.pending:
            self.pending[addr] = []
        self.pending[addr].append(request)
        self.send_next(addr)

    def reconnect(self, addr):

        cls = addr[2]
        netloc = addr[:2]       

        if addr in self.connections:
            conn = self.connections[addr].reconnect()
        else:
            conn = cls(self.upnpy, None, netloc)
            conn.create_socket()
        conn.connect(addr[:2])

        self.connections[addr] = conn

    def send_next(self, addr):
        #import traceback
        #logging.exception('send_next %s %s', addr, "".join(traceback.format_stack()))

        if not self.pending[addr]:
            return
        request = self.pending[addr][0]

        #filter non idempotent method if pipeline is already filled
        if request.method not in ('GET', 'DELETE', 'PUSH', 'HEAD', 'NOTIFY', 'SUBSCRIBE') and \
                (not addr in self.connections or self.connections[addr].pipeline):
            return

        if not addr in self.connections \
                or (not self.connections[addr].connected \
                        and not self.connections[addr].connecting):
            #logging.info('reconnect %r %r', addr, self.connections.get(addr, None))
            self.reconnect(addr)

        conn = self.connections[addr]
        if conn.pipeline and not conn.pipelining:
            return

        self.pending[addr].pop(0)

        conn.send_request(request)
       
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

    def set_if_unset(self, key, value):
        if key not in self:
            self[key] = value
    
def main():
    import upnpy
    u = upnpy.Upnpy()
    s = HTTPServer(u, ssl=False)
    asyncore.loop(map=u._map)
    
if __name__ == '__main__':
    main()
