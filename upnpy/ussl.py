
"""ssl helper functions and class"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import logging
import socket

from persist import DB

from http import HTTPConnection

from uuid import UUID
NAMESPACE_CERT = UUID('acf2b7b8-ba52-4ccb-8484-67c7d17e98bf')

try:
    from M2Crypto import SSL, m2
    sslpackage = 'm2crypto'
except ImportError, e:
    try:
        from OpenSSL import crypto, SSL
        sslpackage = 'openssl'
    except ImportError, e:
        raise type(e)("package python-openssl|python-m2crypto missing")

if sslpackage == 'm2crypto':
    class SSLHTTPConnection(HTTPConnection):
        def __init__(self, *args, **kwargs):
            HTTPConnection.__init__(self, *args, **kwargs)
            self.session = None
            self.ssl_handshake_pending = False
            self.ssl_shutdown_pending = False

            #if not self.client:
            #    self.do_ssl_handshake()

        def create_socket(self):
            HTTPConnection.create_socket(self)
            self.socket = ssl_connection(self.socket, 'control')

        def reuse_session(self, conn):
            try:
                self.socket.set_session(conn.socket.get_session())        
            except AssertionError:
                pass                

        def connect(self, address):
            self.connected = False
            self.connecting = True
            from errno import EINPROGRESS, EALREADY, EWOULDBLOCK, EINVAL, EISCONN
            try:
                self.socket.socket.connect(address)
            except socket.error, e:
                if e.errno in (EINPROGRESS, EALREADY, EWOULDBLOCK) \
                        or e.errno == EINVAL and os.name in ('nt', 'ce'):
                    self.addr = address
                    return
                if e.errno in (0, EISCONN):
                    self.addr = address
                    self.handle_connect_event()
                raise

        def handle_connect_event(self):
            self.socket.setup_ssl()
            self.socket.set_connect_state()
            if self.socket.connect_ssl():
                self.connecting = False
                self.connected = True
            else:
                self.ssl_handshake_pending = True

        def do_ssl_handshake(self):
            if self.client:
                if self.socket.connect_ssl():
                    self.ssl_handshake_pending = False
                    self.connecting = False
                    self.connected = True
                else:
                    self.ssl_handshake_pending = True
            else:
                if self.socket.accept_ssl():
                    self.ssl_handshake_pending = False
                    self.connecting = False
                    self.connected = True
                else:
                    self.ssl_handshake_pending = True

        def do_ssl_shutdown(self):
            self.socket.close()
            self.logger.info('do_ssl_shutdown : %d' % self.socket.get_shutdown())
            if self.socket.get_shutdown() == m2.SSL_SENT_SHUTDOWN | m2.SSL_RECEIVED_SHUTDOWN:
                self.ssl_shutdown_pending = False
                self.connected = False
                self.close()
                        
        def handle_read_event(self):
            try:
                if self.ssl_handshake_pending:
                    self.do_ssl_handshake()
                elif self.ssl_shutdown_pending:
                    self.do_ssl_shutdown()
                else:
                    HTTPConnection.handle_read_event(self)
            except SSL.SSLError, e:
                self.logger.error(e)
                self.socket.clear()
                self.close()

        def handle_write_event(self):
            try:
                if self.ssl_handshake_pending:
                    self.do_ssl_handshake()
                elif self.ssl_shutdown_pending:
                    self.do_ssl_shutdown()
                else:
                    HTTPConnection.handle_write_event(self)
            except SSL.SSLError, e:
                self.logger.error(e)
                self.socket.clear()
                self.close()

        def handle_close(self):
            if self.connected == True and not self.ssl_shutdown_pending:
                self.ssl_shutdown_pending = True 
                self.do_ssl_shutdown()

    def ssl_connection(socket, type=None):

        ctx = SSL.Context('tlsv1')
        ctx.set_info_callback(_ssl_info_callback)
        ctx.set_verify(SSL.verify_peer, 0, callback=_ssl_verify_peer)  #request client cert

        if type:
            with certificate(type) as certfile:
                logging.error('certfile %s', certfile)
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
            logger.info("LOOP: %s: %s", state, m2.ssl_get_state_v(ssl_ptr))
            return

        if (where & m2.SSL_CB_EXIT):
            if not ret:
                logger.info("FAILED: %s: %s", state, m2.ssl_get_state_v(ssl_ptr))
            else:
                logger.info("INFO: %s: %s", state, m2.ssl_get_state_v(ssl_ptr))
            return

        if (where & m2.SSL_CB_ALERT):
            if (where & m2.SSL_CB_READ):
                w = 'read'
            else:
                w = 'write'
            logger.info("ALERT: %s: %s: %s", \
                w, m2.ssl_get_alert_type_v(ret), m2.ssl_get_alert_desc_v(ret))
            return

    def _ssl_verify_peer(ssl_ctx_ptr, x509_ptr, errnum, errdepth, ok):
        logging.getLogger('http.ssl').info('verify %s %s %s %s %s', ssl_ctx_ptr, x509_ptr, errnum, errdepth, ok)
        # Deprecated
        return True

    class certificate(object):

        def __init__(self, type):
            with DB() as db:
                try:
                    self.pem = db['certfile.%s' % type]
                except KeyError:
                    cert, key =_gen_certificate(type)
                    self.pem = db['certfile.%s' % type] = cert.as_pem() + key.as_pem(cipher=None)

        def __enter__(self):
            from tempfile import NamedTemporaryFile
            self.certfile = cf = NamedTemporaryFile('w', bufsize=0, suffix='.pem')
            cf.write(self.pem)
            return cf.name

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.certfile.close()

    def get_peer_certificate(conn):
        return conn.get_peer_cert()

    def cert_uuid(cert):
        """Generate a UUID from the SHA-256 hash of a certificate."""

        der = cert.as_der()

         #cf uuid.py
        from hashlib import sha256
        hash = sha256(NAMESPACE_CERT.bytes + der).digest()

        return UUID(bytes=hash[:16], version=5)    

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

    class SSLHTTPConnection(HTTPConnection):
        def __init__(self, *args, **kwargs):
            HTTPConnection.__init__(self, *args, **kwargs)
            self.ssl_handshake_pending = True
            self.ssl_shutdown_pending = False

        def create_socket(self):
            HTTPConnection.create_socket(self)
            self.socket = ssl_connection(self.socket, 'control')

        def reuse_session(self, conn):
            try:
                self.socket.set_session(conn.socket.get_session())        
            except AssertionError:
                pass                

        def do_ssl_handshake(self):
            try:
                self.socket.do_handshake()
            except SSL.WantReadError, SSL.WantWriteError:
                pass
            else:
                self.ssl_handshake_pending = False

        def do_ssl_shutdown(self):
            self.logger.info('do_ssl_shutdown : %d' % self.socket.get_shutdown())
            try:
                if self.socket.shutdown():
                    self.logger.info('do_ssl_shutdown finished : %d' % self.socket.get_shutdown())
                    self.ssl_shutdown_pending = False
                    HTTPConnection.handle_close(self)
            except Exception, e:
                self.logger.exception('do_ssl_shutdown error : %s', e)
                self.ssl_shutdown_pending = False
                HTTPConnection.handle_close(self)


        def handle_read_event(self):
            try:
                if self.ssl_handshake_pending:
                    self.do_ssl_handshake()
                elif self.ssl_shutdown_pending:
                    self.do_ssl_shutdown()
                else:
                    HTTPConnection.handle_read_event(self)
            except SSL.ZeroReturnError:
                self.handle_close()

        def handle_write_event(self):
            try:
                if self.ssl_handshake_pending:
                    self.do_ssl_handshake()
                elif self.ssl_shutdown_pending:
                    self.do_ssl_shutdown()
                else:
                    HTTPConnection.handle_write_event(self)
            except SSL.ZeroReturnError:
                self.handle_close()
 
        def handle_close(self):
            if self.connected == True and not self.ssl_shutdown_pending:
                self.ssl_shutdown_pending = True
                self.do_ssl_shutdown()

        #def writable(self):
        #    return HTTPConnection.writable(self) or self.ssl_shutdown_pending or self.ssl_handshake_pending


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

    def get_peer_certificate(conn):
        return conn.get_peer_certificate()

    def cert_uuid(cert):
        """Generate a UUID from the SHA-256 hash of a certificate."""

        der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)   

         #cf uuid.py
        from hashlib import sha256
        hash = sha256(NAMESPACE_CERT.bytes + der).digest()

        return UUID(bytes=hash[:16], version=5)    

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


def _get_cn(type):

    import ifaces
    return "upnpy_%s_%s" % (type, next(ifaces.get_addrs(ifaces.AF_PACKET),('',''))[1])
