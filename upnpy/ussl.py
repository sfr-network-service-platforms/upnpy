
"""ssl helper functions and class"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import logging
import socket
import errno
from persist import DB
import ssl

import gevent.ssl, gevent.socket
from gevent.socket import timeout_default

try:
    from M2Crypto_ import SSL, m2
    sslpackage = 'm2crypto'
except ImportError, e:
    try:
        from OpenSSL import crypto, SSL
        sslpackage = 'openssl'
    except ImportError, e:
        raise type(e)("package python-openssl|python-m2crypto missing")

if sslpackage == 'm2crypto':

    def ssl_connection(socket, type=None):

        ctx = SSL.Context('tlsv1')
        ctx.set_info_callback(_ssl_info_callback)
        ctx.set_verify(SSL.verify_peer, 0, callback=_ssl_verify_peer)  #request client cert

        if type:
            with certificate_file(type) as certfile:
                ctx.load_cert(certfile)

            if type == 'device':
                ctx.set_session_cache_mode(m2.SSL_SESS_CACHE_SERVER)
                ctx.set_session_id_ctx(_get_cn(type))
                
        conn = SSL.Connection(ctx, socket)
        #conn.setup_ssl()
        return conn

    def _ssl_info_callback(where, ret, ssl_ptr):

        logger = logging.getLogger('http.ssl')

        w = where & ~m2.SSL_ST_MASK
        if (w & m2.SSL_ST_CONNECT):
            state = "SSL connect"
        elif (w & m2.SSL_ST_ACCEPT):
            state = "SSL accept"
        else:
            state = "SSL state unknown"

        if (where & m2.SSL_CB_LOOP):
            logger.debug("LOOP: %s: %s", state, m2.ssl_get_state_v(ssl_ptr))
            return

        if (where & m2.SSL_CB_EXIT):
            if not ret:
                logger.error("FAILED: %s: %s", state, m2.ssl_get_state_v(ssl_ptr))
            else:
                logger.debug("INFO: %s: %s", state, m2.ssl_get_state_v(ssl_ptr))
            return

        if (where & m2.SSL_CB_ALERT):
            if (where & m2.SSL_CB_READ):
                w = 'read'
            else:
                w = 'write'
            logger.debug("ALERT: %s: %s: %s", \
                w, m2.ssl_get_alert_type_v(ret), m2.ssl_get_alert_desc_v(ret))
            return

    def _ssl_verify_peer(ssl_ctx_ptr, x509_ptr, errnum, errdepth, ok):
        logging.getLogger('http.ssl').debug('verify %s %s %s %s %s', ssl_ctx_ptr, x509_ptr, errnum, errdepth, ok)
        # Deprecated
        return True


    def get_peer_certificate(conn):
        return conn.get_peer_cert()


    def _gen_certificate(type):

        from M2Crypto import EVP, RSA, X509, ASN1
        import time

        # create a key pair
        k = EVP.PKey()
        k.assign_rsa(RSA.gen_key(2048, m2.RSA_F4, lambda:None))

        # create a self-signed cert
        cert = X509.X509()
        cert.get_subject().C = "FR"
        cert.get_subject().O = "SFR"
        cert.get_subject().CN = _get_cn(type)
        cert.set_serial_number(1000)

        now = ASN1.ASN1_UTCTIME()
        now.set_time(long(time.time()))
        cert.set_not_before(now)
        
        expire = ASN1.ASN1_UTCTIME()
        expire.set_time(long(time.time())+10*365*24*60*60)
        cert.set_not_after(expire)

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        return cert, k

elif sslpackage == 'openssl':

    def ssl_connection(socket, type=None):

        ctx = SSL.Context(SSL.TLSv1_METHOD)
        if type:
            cert, key = certificate(type)
            ctx.use_certificate(cert)
            ctx.use_privatekey(key)

            if type == 'device':
                ctx.set_verify(SSL.VERIFY_PEER, _verify_peer)  #request client cert
                #ctx.set_session_cache_mode(SSL.SESS_CACHE_SERVER)

        return SSL.Connection(ctx, socket)

    _PROTO_MAPPING = dict((getattr(ssl, 'PROTOCOL_%s'%v, None), getattr(SSL, '%s_METHOD'%v, None))
                          for v in ['SSLv2', 'SSLv23', 'SSLv3', 'TLSv1', 'TLSv1_1', 'TLSv1_2'])

    def sslwrap(sock, server_side,
                keyfile, certfile,
                cert_reqs, ssl_version,
                ca_certs, ciphers=None):

        ctx = SSL.Context(_PROTO_MAPPING[ssl_version])

        ctx.use_certificate(certfile)
        ctx.use_privatekey(keyfile)

        ctx.set_verify(cert_reqs, _verify_peer)
        if ca_certs:
            ctx.load_verify_locations(ca_certs)            
        else:
            ctx.set_default_verify_paths()
        if ciphers:
            ctx.set_cipher_list(ciphers)

        conn = SSL.Connection(ctx, sock)
        if server_side:
            conn.set_accept_state()

        return conn

    class _SSLSocket(object):

        def read(self, len=1024):
            """Read up to LEN bytes and return them.
            Return zero-length string on EOF."""
            while True:
                try:
                    return self._sslobj.read(len)
                except SSL.WantReadError:
                    if self.timeout == 0.0:
                        raise
                    self._wait(self._read_event, timeout_exc=gevent.ssl._SSLErrorReadTimeout)
                except SSL.WantWriteError:
                    if self.timeout == 0.0:
                        raise
                    # note: using _SSLErrorReadTimeout rather than _SSLErrorWriteTimeout below is intentional
                    self._wait(self._write_event, timeout_exc=gevent.ssl._SSLErrorReadTimeout)
                    
                except Exception, e:
                    if e.args == (-1, 'Unexpected EOF') and self.suppress_ragged_eofs:
                        return ''
                    else:
                        raise

        def write(self, data):
            """Write DATA to the underlying SSL channel.  Returns
            number of bytes of DATA actually transmitted."""
            while True:
                try:
                    return self._sslobj.write(data)
                except SSL.WantReadError:
                    if self.timeout == 0.0:
                        raise
                    self._wait(self._read_event, timeout_exc=gevent.ssl._SSLErrorWriteTimeout)
                except SSL.WantWriteError:
                    if self.timeout == 0.0:
                        raise
                    self._wait(self._write_event, timeout_exc=gevent.ssl._SSLErrorWriteTimeout)
        
        def getpeercert(self, binary_form=False):
            """Returns a formatted version of the data in the
            certificate provided by the other end of the SSL channel.
            Return None if no certificate was provided, {} if a
            certificate was provided, but not validated."""
            return self._sslobj.get_peer_certificate()

        def send(self, data, flags=0, timeout=timeout_default):
            if timeout is timeout_default:
                timeout = self.timeout
            if self._sslobj:
                if flags != 0:
                    raise ValueError(
                        "non-zero flags not allowed in calls to send() on %s" %
                        self.__class__)
                while True:
                    try:
                        v = self._sslobj.write(data)
                    except SSL.WantReadError:
                        if self.timeout == 0.0:
                            return 0
                        self._wait(self._read_event)
                    except SSL.WantWriteError:
                        if self.timeout == 0.0:
                            return 0
                        self._wait(self._write_event)
                    else:
                        return v
            else:
                return socket.send(self, data, flags, timeout)

        def _sslobj_shutdown(self):
            while True:
                try:
                    return self._sslobj.shutdown()
                except Exception, e:
                    if e.args == (-1, 'Unexpected EOF') and self.suppress_ragged_eofs:
                        return ''
                    else:
                        raise
                except SSL.WantReadError:
                    if self.timeout == 0.0:
                        raise
                    self._wait(self._read_event, timeout_exc=gevent.ssl._SSLErrorReadTimeout)
                except SSL.WantWriteError:
                    if self.timeout == 0.0:
                        raise
                    self._wait(self._write_event, timeout_exc=gevent.ssl._SSLErrorWriteTimeout)

        def recv_into(self, buffer, nbytes=None, flags=0):
            if buffer and (nbytes is None):
                nbytes = len(buffer)
            elif nbytes is None:
                nbytes = 1024
            if self._sslobj:
                if flags != 0:
                    raise ValueError(
                        "non-zero flags not allowed in calls to recv_into() on %s" %
                        self.__class__)
                while True:
                    try:
                        tmp_buffer = self.read(nbytes)
                        v = len(tmp_buffer)
                        buffer[:v] = tmp_buffer
                        return v
                    except SSL.WantReadError:
                        if self.timeout == 0.0:
                            raise
                        self._wait(self._read_event)
                        continue
            else:
                return socket.recv_into(self, buffer, nbytes, flags)


        def do_handshake(self):
            """Perform a TLS/SSL handshake."""
            while True:
                try:
                    return self._sslobj.do_handshake()

                except SSL.WantReadError:
                    if self.timeout == 0.0:
                        raise
                    self._wait(self._read_event, timeout_exc=gevent.ssl._SSLErrorHandshakeTimeout)

                except SSL.WantWriteError:
                    if self.timeout == 0.0:
                        raise
                    self._wait(self._write_event, timeout_exc=gevent.ssl._SSLErrorHandshakeTimeout)


    def _verify_peer(conn, x509, err, depth, code):
        #logging.debug('_verify_peer : %r, %r, %r, %r, %r', conn, x509, err, depth, code)
        return True


    def certificate(type):

        with DB() as db:
            try:
                pem = db['certfile.%s' % type]
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
                key = crypto.load_privatekey(crypto.FILETYPE_PEM, pem)
            except KeyError:
                cert, key =_gen_certificate(type)
                pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)\
                    + crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
                db['certfile.%s' % type] = pem

        return (cert, key)

    def get_peer_info(sock):
        cert = sock.getpeercert()
        if not cert:
            return
        return crypto.dump_certificate(crypto.FILETYPE_ASN1, cert), cert.get_subject().CN


    def _gen_certificate(type):

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "FR"
        cert.get_subject().O = "SFR"
        cert.get_subject().CN = _get_cn(type)
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        return cert, k

class SSLSocket(_SSLSocket, gevent.ssl.SSLSocket):

    def __init__(self, sock, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=ssl.CERT_NONE,
                 ssl_version=ssl.PROTOCOL_SSLv23, ca_certs=None,
                 do_handshake_on_connect=True,
                 suppress_ragged_eofs=True,
                 ciphers=None):

        gevent.socket.socket.__init__(self, _sock=sock)

        if certfile and not keyfile:
            keyfile = certfile
        # see if it's connected
        try:
            socket.socket.getpeername(self)
        except socket.error, e:
            if e[0] != errno.ENOTCONN:
                raise
            # no, no connection yet
            self._sslobj = None
        else:
            # yes, create the SSL object
            if ciphers is None:
                self._sslobj = sslwrap(self._sock, server_side,
                                            keyfile, certfile,
                                            cert_reqs, ssl_version, ca_certs)
            else:
                self._sslobj = sslwrap(self._sock, server_side,
                                            keyfile, certfile,
                                            cert_reqs, ssl_version, ca_certs,
                                            ciphers)
            if do_handshake_on_connect:                
                self.do_handshake()

        self.keyfile = keyfile
        self.certfile = certfile
        self.cert_reqs = cert_reqs
        self.ssl_version = ssl_version
        self.ca_certs = ca_certs
        self.ciphers = ciphers
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self._makefile_refs = 0

def wrap_socket(sock, keyfile=None, certfile=None,
                server_side=False, cert_reqs=gevent.ssl.CERT_NONE,
                ssl_version=gevent.ssl.PROTOCOL_SSLv23, ca_certs=None,
                do_handshake_on_connect=True,
                suppress_ragged_eofs=True, ciphers=None):
    """Create a new :class:`SSLSocket` instance."""
    return SSLSocket(sock, keyfile=keyfile, certfile=certfile,
                     server_side=server_side, cert_reqs=cert_reqs,
                     ssl_version=ssl_version, ca_certs=ca_certs,
                     do_handshake_on_connect=do_handshake_on_connect,
                     suppress_ragged_eofs=suppress_ragged_eofs,
                     ciphers=ciphers)

_CERTFILES = dict()
def certificate_file(type):

    if type in _CERTFILES:
        return _CERTFILES[type].name

    with DB() as db:
        try:
            pem = db['certfile.%s' % type]
        except KeyError:
            cert, key = _gen_certificate(type)
            pem = db['certfile.%s' % type] = cert.as_pem() + key.as_pem(cipher=None)

    from tempfile import NamedTemporaryFile
    temp = _CERTFILES[type] = NamedTemporaryFile('w', bufsize=0, suffix='.pem')
    temp.write(pem)

    return temp.name   

# class certificate_file(object):

#     def __init__(self, type):
#         with DB() as db:
#             try:
#                 self.pem = db['certfile.%s' % type]
#             except KeyError:
#                 cert, key = _gen_certificate(type)
#                 self.pem = db['certfile.%s' % type] = cert.as_pem() + key.as_pem(cipher=None)

#     def __enter__(self):
#         from tempfile import NamedTemporaryFile
#         self.certfile = cf = NamedTemporaryFile('w', bufsize=0, suffix='.pem')
#         cf.write(self.pem)
        
#         return cf.name

#     def __exit__(self, exc_type, exc_val, exc_tb):
#         self.certfile.close()


def _get_cn(type):

    import ifaces
    return "upnpy_%s_%s" % (type, next(ifaces.get_addrs(ifaces.AF_PACKET),('',''))[1])
