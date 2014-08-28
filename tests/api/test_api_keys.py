from .base import BaseFlaskTest
import json
import re
import unittest


class PostApiKeyList(BaseFlaskTest):
    def post_api_key(self, username, password):
        return self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header(username, password),
        })

    def test_should_return_401_with_invalid_user(self):
        response = self.post_api_key('baduser', 'badpass')

        self.assertEqual(response.status_code, 401)

    def test_should_set_www_authenticate_header_with_invalid_user(self):
        response = self.post_api_key('baduser', 'badpass')

        self.assertEqual(response.headers['WWW-Authenticate'], 'API-Key')

    def test_should_return_401_with_invalid_password(self):
        response = self.post_api_key('alice', 'badpass')

        self.assertEqual(response.status_code, 401)

    def test_should_set_www_authenticate_header_with_invalid_password(self):
        response = self.post_api_key('alice', 'badpass')

        self.assertEqual(response.headers['WWW-Authenticate'], 'API-Key')

    def test_should_return_201(self):
        response = self.post_api_key('alice', 'apass')
        self.assertEqual(response.status_code, 201)

    def test_should_set_location_header(self):
        response = self.post_api_key('alice', 'apass')
        self.assertTrue(re.search(
            r'^http://localhost[:\d+]?/v1/api-keys/\w+:k$',
            response.headers['Location']))

    def test_should_return_valid_api_key(self):
        post_response = self.post_api_key('alice', 'apass')

        data = json.loads(post_response.data)
        self.assertIn('api-key', data)
        api_key = data['api-key']
        self.assertTrue(re.search(r'\w+:k', api_key))

        get_response = self.client.get('/v1/api-keys/%s' % api_key, headers={
            'Authorization': self.basic_auth_header('alice', 'apass'),
        })
        self.assertEqual(get_response.status_code, 200)


class GetApiKey(BaseFlaskTest):
    def setUp(self):
        super(GetApiKey, self).setUp()
        self.alice_key = self.create_api_key('alice', 'apass')
        self.bob_key = self.create_api_key('bob', 'foobob')
        self.charlie_key = self.create_api_key('charlie', 'charles')

    def test_should_return_200_with_owner_credentials(self):
        response = self.client.get('/v1/api-keys/%s' % self.bob_key, headers={
            'Authorization': self.basic_auth_header('bob', 'foobob'),
        })

        self.assertEqual(response.status_code, 200)

    def test_should_return_data_with_owner_credentials(self):
        response = self.client.get('/v1/api-keys/%s' % self.bob_key, headers={
            'Authorization': self.basic_auth_header('bob', 'foobob'),
        })

        data = json.loads(response.data)
        self.assertEqual(data['api-key'], self.bob_key)
        self.assertEqual(data['active'], True)

    def test_should_return_401_with_invalid_credentials(self):
        response = self.client.get('/v1/api-keys/%s' % self.bob_key, headers={
            'Authorization': self.basic_auth_header('baduser', 'badpass'),
        })

        self.assertEqual(response.status_code, 401)

    def test_should_return_404_if_key_does_not_exist(self):
        response = self.client.get('/v1/api-keys/nonsense', headers={
            'Authorization': self.basic_auth_header('charlie', 'charles'),
        })

        self.assertEqual(response.status_code, 404)

    def test_should_return_404_with_other_credentials(self):
        response = self.client.get('/v1/api-keys/%s' % self.bob_key, headers={
            'Authorization': self.basic_auth_header('charlie', 'charles'),
        })

        self.assertEqual(response.status_code, 404)


class PatchApiKey(BaseFlaskTest):
    def setUp(self):
        super(PatchApiKey, self).setUp()
        self.alice_key = self.create_api_key('alice', 'apass')
        self.bob_key = self.create_api_key('bob', 'foobob')
        self.charlie_key = self.create_api_key('charlie', 'charles')

        self.default_test_key = self.bob_key

    def patch_api_keys(self, data, username, password, key=None):
        if key is None:
            key = self.default_test_key

        return self.client.patch('/v1/api-keys/%s' % key, json.dumps(data),
            headers={
                'Authorization': self.basic_auth_header(username, password),
        })

    def test_should_return_200_with_owner_credentials(self):
        response = self.patch_api_keys({'active': False}, 'bob', 'foobob')

        self.assertEqual(response.status_code, 200)

    def test_should_return_updated_api_key_data(self):
        response = self.patch_api_keys({'active': False}, 'bob', 'foobob')

        data = json.loads(response.data)
        self.assertEqual(data['api-key'], self.bob_key)
        self.assertEqual(data['active'], False)


    def test_should_persist_modified_data(self):
        patch_response = self.patch_api_keys({'active': False}, 'bob', 'foobob')

        get_response = self.client.get('/v1/api-keys/%s' % self.bob_key,
            headers={
                'Authorization': self.basic_auth_header('bob', 'foobob'),
        })
        data = json.loads(get_response.data)
        self.assertEqual(data['api-key'], self.bob_key)
        self.assertEqual(data['active'], False)

    def test_should_return_401_with_invalid_credentials(self):
        response = self.patch_api_keys({'active': False}, 'baduser', 'badpass')

        self.assertEqual(response.status_code, 401)

    def test_should_return_404_if_key_does_not_exist(self):
        response = self.patch_api_keys({'active': False}, 'charlie', 'charles',
                key='/v1/api-keys/nonsense')

        self.assertEqual(response.status_code, 404)

    def test_should_return_404_with_other_credentials(self):
        response = self.patch_api_keys({'active': False}, 'charlie', 'charles')

        self.assertEqual(response.status_code, 404)
