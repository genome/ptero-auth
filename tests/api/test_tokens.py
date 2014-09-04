from .base import BaseFlaskTest
import jot
import json
import urllib
import urlparse
import uuid


NAMESPACE = uuid.UUID('66deca4c-4e8a-44ce-a617-3d37bc0bcfaa')


class PostTokens(BaseFlaskTest):
    VALID_CONFIDENTIAL_CLIENTS = [
        {
            'name': 'widget maker v1.1',
            'redirect_uri_regex':
                r'^http://localhost:8008/(resource1)|(resource2)/?(\?.+)?$',
            'default_redirect_uri':
                r'^http://localhost:8008/resource1/12345',
            'allowed_scopes': ['foo', 'bar', 'baz', 'openid'],
            'default_scopes': ['bar', 'baz', 'openid'],
            'audience_for': 'bar',
            'audience_fields': ['posix'],
        },

        {
            'name': 'gidget shaker v1.1',
            'redirect_uri_regex':
                r'^http://localhost:5005/gidget/.+(\?.+)?$',
            'default_redirect_uri':
                r'^http://localhost:5005/gidget/12345',
            'allowed_scopes': ['baz', 'openid'],
            'default_scopes': ['baz', 'openid'],
            'audience_for': 'baz',
            'audience_fields': ['roles'],
        },
    ]

    def setUp(self):
        super(PostTokens, self).setUp()
        self.bob_key = self.create_api_key('bob', 'foobob')
        self.valid_client_data = []
        for vcc_data in self.VALID_CONFIDENTIAL_CLIENTS:
            self.valid_client_data.append(self.register_client('alice', 'apass',
                **vcc_data))

        self.redirect_uri = 'http://localhost:8008/resource1/asdf'

    def authorize_url(self, response_type='code', scopes=None):
        args = {
            'client_id': self.valid_client_data[0]['client_id'],
            'response_type': response_type,
            'redirect_uri': self.redirect_uri,
            'state': 'OPAQUE VALUE FOR PREVENTING FORGERY ATTACKS',
        }

        if scopes:
            args['scope'] = ' '.join(scopes)

        return '/v1/authorize?' + urllib.urlencode(args)

    def get_authorization(self, scopes=None):
        response = self.client.get(self.authorize_url(scopes=scopes),
                headers={'Authorization': 'API-Key ' + self.bob_key})
        url = urlparse.urlparse(response.headers['Location'])
        args = urlparse.parse_qs(url.query)

        for name,value in args.items():
            args[name] = value[0]

        args['redirect_uri'] = response.headers['Location'].split('?')[0]
        return args

    @property
    def client_id(self):
        return self.valid_client_data[0]['client_id']

    @property
    def client_secret(self):
        return self.valid_client_data[0]['client_secret']

    def get_post_data(self, authorize_args, scopes=None):
        args = {
            'code': authorize_args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': authorize_args['redirect_uri'],
        }
        if scopes:
            args['scope'] = ' '.join(scopes)

        return urllib.urlencode(args)

    def _get_response_data(self, response):
        return json.loads(response.data)

    def test_should_return_401_with_bad_client_credentials(self):
        response = self.client.post('/v1/tokens',
                data=self.get_post_data(self.get_authorization()),
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        'invalid-secret'),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        self.assertEqual(response.status_code, 401)

    def test_should_return_200_with_valid_client_credentials(self):
        response = self.client.post('/v1/tokens',
                data=self.get_post_data(self.get_authorization()),
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        self.assertEqual(response.status_code, 200)

    def test_should_return_valid_access_token(self):
        response = self.client.post('/v1/tokens',
                data=self.get_post_data(self.get_authorization()),
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        data = self._get_response_data(response)
        self.assertIn('access_token', data)

    def test_should_return_valid_id_token(self):
        response = self.client.post('/v1/tokens',
                data=self.get_post_data(
                    self.get_authorization(scopes=['bar', 'foo', 'openid'])),
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        data = self._get_response_data(response)
        self.assertIn('id_token', data)

        id_token_jws = jot.deserialize(data['id_token'])
        self.assertTrue(id_token_jws.verify_with(self.public_key))

        id_token = id_token_jws.payload
        self.assertTrue(id_token.is_valid)
        self.assertEqual(len(id_token.claims['aud']), 1)
        self.assertTrue(id_token.has_audience(
            self.valid_client_data[0]['client_id']))

        self.assertTrue(id_token.get_claim_from_namespace(NAMESPACE, 'posix'))
        self.assertFalse(id_token.get_claim_from_namespace(NAMESPACE, 'roles'))

    def test_should_return_multiple_audiences(self):
        response = self.client.post('/v1/tokens',
                data=self.get_post_data(self.get_authorization()),
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        data = self._get_response_data(response)
        id_token_jws = jot.deserialize(data['id_token'])

        id_token = id_token_jws.payload
        self.assertTrue(id_token.has_audience(
            self.valid_client_data[0]['client_id']))
        self.assertTrue(id_token.has_audience(
            self.valid_client_data[1]['client_id']))

        self.assertTrue(id_token.get_claim_from_namespace(NAMESPACE, 'posix'))
        self.assertTrue(id_token.get_claim_from_namespace(NAMESPACE, 'roles'))

    def test_should_return_401_with_invalid_redirect_uri(self):
        authorize_args = self.get_authorization()
        post_data = urllib.urlencode({
            'code': authorize_args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://localhost:12000/something/invalid',
        })

        response = self.client.post('/v1/tokens', data=post_data,
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })
        self.assertEqual(response.status_code, 401)

    def test_should_return_401_with_repeat_code(self):
        post_data = self.get_post_data(self.get_authorization())
        response1 = self.client.post('/v1/tokens', data=post_data,
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        response2 = self.client.post('/v1/tokens', data=post_data,
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })
        self.assertEqual(response2.status_code, 401)
