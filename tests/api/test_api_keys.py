from .base import BaseFlaskTest
import json
import re
import unittest


class PostApiKeyList(BaseFlaskTest):
    def test_should_return_401_with_invalid_user(self):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('baduser', 'badpass'),
        })

        self.assertEqual(response.status_code, 401)

    def test_should_set_www_authenticate_header_with_invalid_user(self):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('baduser', 'badpass'),
        })

        self.assertEqual(response.headers['WWW-Authenticate'], 'API-Key')

    def test_should_return_401_with_invalid_password(self):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('alice', 'badpass'),
        })

        self.assertEqual(response.status_code, 401)

    def test_should_set_www_authenticate_header_with_invalid_password(self):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('alice', 'badpass'),
        })

        self.assertEqual(response.headers['WWW-Authenticate'], 'API-Key')

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
        post_response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header('alice', 'apass'),
        })
        data = json.loads(post_response.data)
        self.assertIn('api-key', data)
        api_key = data['api-key']
        self.assertTrue(re.search(r'\w+:k', api_key))

        get_response = self.client.get('/v1/api-keys/%s' % api_key, headers={
            'Authorization': self.basic_auth_header('alice', 'apass'),
        })
        self.assertEqual(get_response.status_code, 200)
