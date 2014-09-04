from .. import rsa_key
from .base import BaseFlaskTest
import json
import re


CONFIDENTIAL_CLIENT_PORT = 8008


class PostClientsList(BaseFlaskTest):
    VALID_CONFIDENTIAL_CLIENT = {
        'name': 'widget maker v1.1',
        'redirect_uri_regex': '^http://localhost:'
            + str(CONFIDENTIAL_CLIENT_PORT)
            + r'/(resource1)|(resource2)/?(\?.+)?$',
        'default_redirect_uri': 'http://localhost:'
            + str(CONFIDENTIAL_CLIENT_PORT)
            + '/resource1/12345',
        'allowed_scopes': ['foo', 'bar', 'baz'],
        'default_scopes': ['bar', 'baz'],
        'audience_for': 'bar',
        'audience_claims': ['posix'],
        'public_key': {
            'kid': 'SOME FANCY KID',
            'key': rsa_key.RESOURCE_PUBLIC_KEY.exportKey(),
            'alg': 'RSA1_5',
            'enc': 'A128CBC-HS256',
        },
    }

    def test_should_return_401_with_no_credentials(self):
        response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT))

        self.assertEqual(response.status_code, 401)

    def test_should_return_401_with_invalid_credentials(self):
        response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT),
                headers={
                    'Authorization': self.basic_auth_header('alice', 'nopass'),
                })

        self.assertEqual(response.status_code, 401)

    def test_should_return_403_for_non_admin_user(self):
        response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT),
                headers={
                    'Authorization': self.basic_auth_header('bob', 'foobob'),
                })

        self.assertEqual(response.status_code, 403)

    def test_should_return_201_with_admin_credentials(self):
        response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT),
                headers={
                    'Authorization': self.basic_auth_header('alice', 'apass'),
                })

        self.assertEqual(response.status_code, 201)

    def test_should_set_location_header_with_admin_credentials(self):
        response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT),
                headers={
                    'Authorization': self.basic_auth_header('alice', 'apass'),
                })

        self.assertTrue(re.match('http://localhost/v1/clients/\w+',
            response.headers['Location']))

    def test_should_return_client_data_with_admin_credentials(self):
        response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT),
                headers={
                    'Authorization': self.basic_auth_header('alice', 'apass'),
                })

        response_data = json.loads(response.data)

        self.compare_client_data(response_data, self.VALID_CONFIDENTIAL_CLIENT)

    def test_should_persist_client_data_with_admin_credentials(self):
        post_response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT),
                headers={
                    'Authorization': self.basic_auth_header('alice', 'apass'),
                })

        get_response = self.client.get(post_response.headers['Location'],
                headers={
                    'Authorization': self.basic_auth_header('alice', 'apass'),
                })
        self.assertEqual(get_response.status_code, 200)

        response_data = json.loads(get_response.data)

        self.compare_client_data(response_data, self.VALID_CONFIDENTIAL_CLIENT)

    CLIENT_DATA_COMPARISON_WRAPPERS = {
        'type': lambda x: x,
        'name': lambda x: x,
        'redirect_uri_regex': lambda x: x,
        'default_redirect_uri': lambda x: x,
        'allowed_scopes': set,
        'default_scopes': set,
        'audience_for': lambda x: x,
        'audience_claims': set,
        'public_key': lambda x: x
    }
    def compare_client_data(self, actual, expected):
        for posted_key, posted_value in expected.iteritems():
            wrapper = self.CLIENT_DATA_COMPARISON_WRAPPERS[posted_key]
            self.assertEqual(wrapper(actual[posted_key]), wrapper(posted_value))
