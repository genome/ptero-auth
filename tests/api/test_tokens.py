from .base import BaseFlaskTest
import json
import urllib
import urlparse


CONFIDENTIAL_CLIENT_PORT = 8008


class PostTokens(BaseFlaskTest):
    VALID_CONFIDENTIAL_CLIENT = {
        'type': 'confidential',
        'name': 'widget maker v1.1',
        'redirect_uri_regex': '^http://localhost:'
            + str(CONFIDENTIAL_CLIENT_PORT)
            + r'/(resource1)|(resource2)/?(\?.+)?$',
        'allowed_scopes': ['foo', 'bar', 'baz', 'openid'],
        'default_scopes': ['bar', 'baz', 'openid'],
        'audience_for': 'bar',
    }

    def setUp(self):
        super(PostTokens, self).setUp()
        self.bob_key = self.create_api_key('bob', 'foobob')
        self.valid_client_data = self.register_client('alice', 'apass',
                **self.VALID_CONFIDENTIAL_CLIENT)

        self.redirect_uri = ('http://localhost:%d/resource1/asdf'
                % CONFIDENTIAL_CLIENT_PORT)

        self.authorize_args = self.get_authorization()

    def authorize_url(self, response_type='code', scopes=None):
        args = {
            'client_id': self.valid_client_data['client_id'],
            'response_type': response_type,
            'redirect_uri': self.redirect_uri,
            'state': 'OPAQUE VALUE FOR PREVENTING FORGERY ATTACKS',
        }

        if scopes:
            args['scope'] = ' '.join(scopes)

        return '/v1/authorize?' + urllib.urlencode(args)

    def get_authorization(self):
        response = self.client.get(self.authorize_url(),
                headers={'Authorization': 'API-Key ' + self.bob_key})
        url = urlparse.urlparse(response.headers['Location'])
        args = urlparse.parse_qs(url.query)

        for name,value in args.items():
            args[name] = value[0]

        args['redirect_uri'] = response.headers['Location'].split('?')[0]
        return args

    @property
    def client_id(self):
        return self.valid_client_data['client_id']

    @property
    def client_secret(self):
        return self.valid_client_data['client_secret']

    def get_post_data(self):
        return urllib.urlencode({
            'code': self.authorize_args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': self.authorize_args['redirect_uri'],
        })

    def test_should_return_401_with_bad_client_credentials(self):
        response = self.client.post('/v1/tokens', data=self.get_post_data(),
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        'invalid-secret'),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        self.assertEqual(response.status_code, 401)

    def test_should_return_200_with_valid_client_credentials(self):
        response = self.client.post('/v1/tokens', data=self.get_post_data(),
                headers={
                    'Authorization': self.basic_auth_header(self.client_id,
                        self.client_secret),
                    'Contet-Type': 'application/x-www-form-urlencoded',
                })

        self.assertEqual(response.status_code, 200)

    def test_should_return_401_with_invalid_redirect_uri(self):
        post_data = urllib.urlencode({
            'code': self.authorize_args['code'],
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
        post_data = self.get_post_data()
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
