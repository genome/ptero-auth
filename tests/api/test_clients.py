from .base import BaseFlaskTest
import json
import re
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

        for posted_key, posted_value in (
                self.VALID_CONFIDENTIAL_CLIENT.iteritems()):
            self.assertEqual(response_data[posted_key], posted_value)

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

        for posted_key, posted_value in (
                self.VALID_CONFIDENTIAL_CLIENT.iteritems()):
            self.assertEqual(response_data[posted_key], posted_value)
