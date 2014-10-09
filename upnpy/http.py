
"""http handling"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import gevent.pywsgi
import os, socket
import logging
import time
import urlparse


class HTTPHandler(object):

    def __init__(self, server):
        self.server = server

    def __call__(self, env, start_response):

        if env['PATH_INFO'] == '/_notification' and \
                env.get('HTTP_SID', None) in self.server.upnpy._subscriptions:
            return self.server.upnpy._subscriptions[env['HTTP_SID']].notify(env, start_response)

        elif len(env['PATH_INFO'].split('/')) > 2:
            from wsgiref.util import shift_path_info
            device = shift_path_info(env)
            if device in self.server.upnpy.devices:
                return self.server.upnpy.devices[device]._dispatch(env, start_response)

        import utils
        start_response(utils.status(404), [])
        return []

class WSGIHandler(gevent.pywsgi.WSGIHandler):

    import upnpy
    import sys
    SERVER_HEADER = ('Server', 'Upnpy/%s, UPnP/%s, Python/%s' % (upnpy.__version__, upnpy.UPNP_VERSION, sys.version.split()[0]))

    def log_request(self):
        #dont log 1xx, 2xx, 3xx responses
        if (getattr(self, 'status', None) or '000').split()[0][0] in "123":
            return
        gevent.pywsgi.WSGIHandler.log_request(self)

    def finalize_headers(self):
        super(WSGIHandler, self).finalize_headers()
        self.response_headers.append(self.SERVER_HEADER)

    def get_environ(self):
        env = super(WSGIHandler, self).get_environ()

        der_cn = None
        if self.server.ssl_args:
            import ussl
            der_cn = ussl.get_peer_info(self.socket)

        import protection
        env['upnp.dp.identities'], env['upnp.dp.roles'] = \
            protection.get_identities_roles(env, *(der_cn or tuple()))
        
        return env

class HTTPServer():
    
    BASE_PORT = 49152

    def __init__(self, upnpy, ssl=False):
        self.upnpy = upnpy
        self.ssl = ssl

        self.server_port = self.BASE_PORT
        while True:
            try:

                kwargs = dict()
                if self.ssl:
                    import ussl, ssl
                    kwargs['certfile'], kwargs['keyfile'] = ussl.certificate('device') 
                    kwargs['cert_reqs'] = ssl.CERT_OPTIONAL
                    #kwargs['ca_certs'] = 0

                self.server = gevent.pywsgi.WSGIServer((self.upnpy.server_address, self.server_port), HTTPHandler(self), log=FileLogger('http'), handler_class=WSGIHandler, **kwargs)

                if self.ssl:
                    self.server.wrap_socket = ussl.wrap_socket

                self.server.start()
                break
            except socket.error, e:
                import errno
                if e.errno != errno.EADDRINUSE:
                    raise
            self.server_port += 1

   


class FileLogger(object):

    def __init__(self, name):
        self.logger = logging.getLogger(name)

    def write(self, data):
        self.logger.error(data.strip())

import httplib
class ConnectionPool(type):

    def __init__(cls, name, bases, dict):
        super(ConnectionPool, cls).__init__(name, bases, dict)
        cls.POOL = {}

    def __call__(cls, *args, **kwargs):

        key = (tuple(args), tuple(sorted(kwargs.items())))
        for k, conn in cls.POOL.items():
            if k == key and conn._HTTPConnection__state == httplib._CS_IDLE and conn._HTTPConnection__response == None:
                return conn

        conn = cls.POOL[key] = super(ConnectionPool, cls).__call__(*args, **kwargs)
        return conn

class HTTPConnection(httplib.HTTPConnection, object):
    __metaclass__ = ConnectionPool

    import upnpy
    import sys
    USER_AGENT = ('User-Agent', 'Upnpy/%s, UPnP/%s, Python/%s' % (upnpy.__version__, upnpy.UPNP_VERSION, sys.version.split()[0]))

    def putrequest(self, *args, **kwargs):
        super(HTTPConnection, self).putrequest(*args, **kwargs)
        self.putheader(*self.USER_AGENT)

class HTTPSConnection(httplib.HTTPSConnection, object):
    __metaclass__ = ConnectionPool

    import upnpy
    import sys
    USER_AGENT = ('User-Agent', 'Upnpy/%s, UPnP/%s, Python/%s' % (upnpy.__version__, upnpy.UPNP_VERSION, sys.version.split()[0]))

    def putrequest(self, *args, **kwargs):
        super(HTTPSConnection, self).putrequest(*args, **kwargs)
        self.putheader(*self.USER_AGENT)

def HTTPRequest(url):

    up = urlparse.urlparse(url)
    if up.scheme == 'http':
        return HTTPConnection(up.hostname, up.port)
    elif up.scheme == 'https':
        import ussl
        return HTTPSConnection(up.hostname, up.port, cert_file=ussl.certificate_file('device'))
    else:
        raise NotImplementedError('unknown url scheme %s' % up.scheme)
    

_DESCRIPTIONS = dict()

def describe(url):
    try:
        return type('Response', (object,), dict(
                body=_DESCRIPTIONS[url],
                status=200))

    except KeyError:
        req = HTTPRequest(url)
        up = urlparse.urlparse(url)
        req.request('GET', urlparse.urlunparse(('','')+up[2:]))
        res = req.getresponse(True)
        res.body = res.read()

        if res.status == 200:
            _DESCRIPTIONS[url] = res.body

        return res

