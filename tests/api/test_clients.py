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
