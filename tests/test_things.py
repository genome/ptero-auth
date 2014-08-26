from .base import BaseFlaskTest
import json
import re
import unittest


class PostApiKey(BaseFlaskTest):
#    def test_post_api_keys_should_fail_with_invalid_password(self):
#        pass

    def test_should_return_201(self):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('alice', 'apass'),
        })
        self.assertEqual(response.status_code, 201)

    def test_should_set_location_header(self):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('alice', 'apass'),
        })
        self.assertTrue(re.search(
            r'^http://localhost[:\d+]?/v1/api-keys/\w+:k$',
            response.headers['Location']))

    def test_should_return_valid_api_key(self):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('alice', 'apass'),
        })
        data = json.loads(response.data)
        self.assertIn('api-key', data)
        self.assertTrue(re.search(r'\w+:k', data['api-key']))
#        self.fail('need to query server to see if api key is valid')
