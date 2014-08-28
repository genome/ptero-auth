from .base import BaseFlaskTest
import json
import unittest


CONFIDENTIAL_CLIENT_PORT = 8008


class PostClientsList(BaseFlaskTest):
    VALID_CONFIDENTIAL_CLIENT = {
        'type': 'confidential',
        'name': 'widget maker v1.1',
        'redirect_uri_regex': '^http://localhost:'
            + str(CONFIDENTIAL_CLIENT_PORT)
            + r'/(resource1)|(resource2)/?(\?.+)?$',
    }

    def test_should_return_201_with_admin_credentials(self):
        response = self.client.post('/v1/clients',
                data=json.dumps(self.VALID_CONFIDENTIAL_CLIENT),
                headers={
                    'Authorization': self.basic_auth_header('alice', 'apass'),
                })

        self.assertEqual(response.status_code, 201)

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
