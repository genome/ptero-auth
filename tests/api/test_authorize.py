from .base import BaseFlaskTest
import json
import urllib
import urlparse


CONFIDENTIAL_CLIENT_PORT = 8008


class GetAuthorizeBase(BaseFlaskTest):
    VALID_CONFIDENTIAL_CLIENT = {
        'type': 'confidential',
        'name': 'widget maker v1.1',
        'redirect_uri_regex': '^http://localhost:'
            + str(CONFIDENTIAL_CLIENT_PORT)
            + r'/(resource1)|(resource2)/?(\?.+)?$',
        'allowed_scopes': ['foo', 'bar', 'baz'],
        'default_scopes': ['bar', 'baz'],
        'audience_for': ['bar'],
    }

    def setUp(self):
        super(GetAuthorizeBase, self).setUp()
        self.bob_key = self.create_api_key('bob', 'foobob')
        self.valid_client_data = self.register_client('alice', 'apass',
                **self.VALID_CONFIDENTIAL_CLIENT)

        self.redirect_uri = ('http://localhost:%d/resource1/asdf'
                % CONFIDENTIAL_CLIENT_PORT)

    def authorize_url(self, response_type='code', redirect_uri=None,
            scopes=None):
        if redirect_uri is None:
            redirect_uri = self.redirect_uri

        args = {
            'client_id': self.valid_client_data['client_id'],
            'response_type': response_type,
            'redirect_uri': redirect_uri,
            'state': 'OPAQUE VALUE FOR PREVENTING FORGERY ATTACKS',
        }

        if scopes:
            args['scope'] = ' '.join(scopes)

        return '/v1/authorize?' + urllib.urlencode(args)


class GetAuthorizeGeneral(GetAuthorizeBase):
    def test_should_return_401_with_no_api_key(self):
        response = self.client.get('/v1/authorize')

        self.assertEqual(response.status_code, 401)

    def test_should_return_www_authenticate_header_with_no_api_key(self):
        response = self.client.get('/v1/authorize')

        self.assertEqual(response.headers['WWW-Authenticate'], 'API-Key')


class GetAuthorizeCodeFlow(GetAuthorizeBase):
    def test_should_return_400_with_invalid_redirect_uri(self):
        response = self.client.get(self.authorize_url(
                redirect_uri='http://localhost:12000/something/invalid'),
            headers={'Authorization': 'API-Key ' + self.bob_key})

        self.assertEqual(response.status_code, 400)

    def test_should_return_302_with_api_key(self):
        response = self.client.get(self.authorize_url(),
                headers={'Authorization': 'API-Key ' + self.bob_key})

        self.assertEqual(response.status_code, 302)

    def test_should_redirect_with_authorization_code(self):
        response = self.client.get(self.authorize_url(),
                headers={'Authorization': 'API-Key ' + self.bob_key})

        url = urlparse.urlparse(response.headers['Location'])
        args = urlparse.parse_qs(url.query)

        self.assertIn('code', args)

    def test_should_redirect_to_redirect_uri(self):
        response = self.client.get(self.authorize_url(),
                headers={'Authorization': 'API-Key ' + self.bob_key})

        url, rest = response.headers['Location'].split('?')

        self.assertIn(url, self.redirect_uri)
