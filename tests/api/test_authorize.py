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
        'audience_for': 'bar',
    }

    def setUp(self):
        super(GetAuthorizeBase, self).setUp()
        self.bob_key = self.create_api_key('bob', 'foobob')
        self.confidential_client_data = self.register_client('alice', 'apass',
                **self.VALID_CONFIDENTIAL_CLIENT)

        self.redirect_uri = ('http://localhost:%d/resource1/asdf'
                % CONFIDENTIAL_CLIENT_PORT)

    def public_authorize_url(self, scopes=None, **kwargs):
        args = {
            'client_id': 'ARBITRARY TESTING CLIENT_ID',
            'response_type': 'id_token token',
            'state': 'OPAQUE VALUE FOR PREVENTING FORGERY ATTACKS',
        }

        args.update(kwargs)
        return self._root_authorize_url(args, scopes)

    def confidential_authorize_url(self, scopes=None, **kwargs):
        args = {
            'client_id': self.confidential_client_data['client_id'],
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'state': 'OPAQUE VALUE FOR PREVENTING FORGERY ATTACKS',
        }

        args.update(kwargs)
        return self._root_authorize_url(args, scopes)

    def _root_authorize_url(self, args, scopes=None):
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
        response = self.client.get(self.confidential_authorize_url(
                redirect_uri='http://localhost:12000/something/invalid'),
            headers={'Authorization': 'API-Key ' + self.bob_key})

        self.assertEqual(response.status_code, 400)

    def test_should_return_302_with_api_key(self):
        response = self.client.get(self.confidential_authorize_url(),
                headers={'Authorization': 'API-Key ' + self.bob_key})

        self.assertEqual(response.status_code, 302)

    def test_should_redirect_with_authorization_code(self):
        response = self.client.get(self.confidential_authorize_url(),
                headers={'Authorization': 'API-Key ' + self.bob_key})

        url = urlparse.urlparse(response.headers['Location'])
        args = urlparse.parse_qs(url.query)

        self.assertIn('code', args)

    def test_should_redirect_to_redirect_uri(self):
        response = self.client.get(self.confidential_authorize_url(),
                headers={'Authorization': 'API-Key ' + self.bob_key})

        url, rest = response.headers['Location'].split('?')

        self.assertIn(url, self.redirect_uri)


class GetAuthorizeImplicitFlow(GetAuthorizeBase):
    def _get_frament_data(self, response):
        redirect_uri = response.headers['Location']
        urlobj = urlparse.urlparse(redirect_uri)
        return urlparse.parse_qs(urlobj.fragment)

    def test_should_return_302_with_api_key(self):
        response = self.client.get(self.public_authorize_url(
            scopes=['openid', 'bar']),
            headers={'Authorization': 'API-Key ' + self.bob_key})

        self.assertEqual(response.status_code, 302)

    def test_should_return_access_token(self):
        response = self.client.get(self.public_authorize_url(
            scopes=['openid', 'bar']),
            headers={'Authorization': 'API-Key ' + self.bob_key})

        fragment_data = self._get_frament_data(response)

        self.assertIn('access_token', fragment_data)
        self.assertIn('expires_in', fragment_data)
        self.assertEqual(['Bearer'], fragment_data['token_type'])

    def test_should_error_with_three_scopes(self):
        response = self.client.get(self.public_authorize_url(
            scopes=['openid', 'bar', 'baz']),
            headers={'Authorization': 'API-Key ' + self.bob_key})

        fragment_data = self._get_frament_data(response)

        self.assertIn('error', fragment_data)

    def test_should_error_with_no_audience_scope(self):
        response = self.client.get(self.public_authorize_url(
            scopes=['openid']),
            headers={'Authorization': 'API-Key ' + self.bob_key})

        fragment_data = self._get_frament_data(response)

        self.assertIn('error', fragment_data)

    def test_should_error_with_non_openid_second_scope(self):
        response = self.client.get(self.public_authorize_url(
            scopes=['bar', 'baz']),
            headers={'Authorization': 'API-Key ' + self.bob_key})

        fragment_data = self._get_frament_data(response)

        self.assertIn('error', fragment_data)
