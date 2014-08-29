from Crypto.PublicKey import RSA
from ptero_auth.api.application import create_app
from .. import rsa_key, util
import json
import os
import requests.auth
import unittest
import yaml


_SIGNATURE_KEY = {
    'signature_alg': 'RS256',
    'signature_key': RSA.importKey(rsa_key.TESTING_PRIVATE_KEY),
    'signature_kid': 'testing-key',
}


class BaseFlaskTest(unittest.TestCase):
    def setUp(self):
        if os.environ.get('TEST_POSIX_PROVIDER'):
            user_data = None

        else:
            with open(util.get_test_data_path('test_users.yaml')) as f:
                user_data = yaml.load(f)

        self.app = create_app(user_data=user_data, settings={
            'signature_key': _SIGNATURE_KEY,
            'database_url': 'sqlite://',
            'admin_role': os.environ.get('TEST_ADMIN_ROLE', 'pteroadmin'),
        })
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        self.public_key = _SIGNATURE_KEY['signature_key'].publickey()

    def basic_auth_header(self, username, password):
        return requests.auth._basic_auth_str(username, password)

    def create_api_key(self, username, password):
        response = self.client.post('/v1/api-keys', headers={
            'Authorization': self.basic_auth_header(username, password),
        })

        data = json.loads(response.data)
        return data['api-key']
