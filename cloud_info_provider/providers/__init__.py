import socket

from six.moves.urllib.parse import urlparse

from OpenSSL import SSL


class BaseProvider(object):
    def __init__(self, opts):
        self.opts = opts

    def _get_endpoint_ca_information(self, endpoint_url, insecure=False,
                                     cafile=None,
                                     capath='/etc/grid-security/certificates'):
        '''Return certificate issuer and trusted CAs list of HTTPS endpoint.'''
        ca_info = {
            'issuer': 'UNKNOWN',
            'trusted_cas': ['UNKNOWN']
        }

        if insecure:
            verify = SSL.VERIFY_NONE
        else:
            verify = SSL.VERIFY_PEER

        try:
            scheme = urlparse(endpoint_url).scheme
            host = urlparse(endpoint_url).hostname
            port = urlparse(endpoint_url).port

            if scheme == 'https':
                ctx = SSL.Context(SSL.SSLv23_METHOD)
                ctx.set_options(SSL.OP_NO_SSLv2)
                ctx.set_options(SSL.OP_NO_SSLv3)
                ctx.set_verify(verify, lambda conn, cert, errno, depth, ok: ok)
                if not insecure:
                    ctx.load_verify_locations(cafile=cafile, capath=capath)

                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((host, port))

                client_ssl = SSL.Connection(ctx, client)
                client_ssl.set_connect_state()
                client_ssl.set_tlsext_host_name(host)
                client_ssl.do_handshake()

                cert = client_ssl.get_peer_certificate()
                issuer = self._get_dn(cert.get_issuer())

                client_ca_list = client_ssl.get_client_ca_list()
                trusted_cas = [self._get_dn(ca) for ca in client_ca_list]

                client_ssl.shutdown()
                client_ssl.close()

                ca_info['issuer'] = issuer
                ca_info['trusted_cas'] = trusted_cas
        except SSL.Error:
            # FIXME: should not pass silently
            pass

        return ca_info

    def _get_dn(self, x509name):
        '''Return the DN of an X509Name object.'''
        # XXX shortest/easiest way to get the DN of the X509Name
        # str(X509Name): <X509Name object 'DN'>
        # return str(x509name)[18:-2]
        obj_name = str(x509name)
        start = obj_name.find("'") + 1
        end = obj_name.rfind("'")

        return obj_name[start:end]

    def get_site_info(self, **kwargs):
        return {}

    def get_images(self, **kwargs):
        return {}

    def get_templates(self, **kwargs):
        return {}

    def get_instances(self, **kwargs):
        return {}

    def get_compute_shares(self, **kwargs):
        return {}

    def get_compute_quotas(self, **kwargs):
        return {}

    def get_compute_endpoints(self, **kwargs):
        return {}

    def get_storage_endpoints(self, **kwargs):
        return {}

    @staticmethod
    def populate_parser(parser):
        '''Populate the argparser 'parser' with the needed options.'''
