import unittest
import os
from ptero_auth.settings import get_from_env
from . import rsa_key


class SettingsTest (unittest.TestCase):
    env_to_set = {
        'DATABASE_URL': 'foo1',
        'AUTH_URL': 'http://localhost:8000/',
        'ADMIN_ROLE': 'foo2',
        'SIGNATURE_KEY': rsa_key.AUTH_PRIVATE_KEY.exportKey(),
    }

    def setUp(self):
        self.saved_env = {}
        for name, value in self.env_to_set.items():
            self.saved_env[name] = os.environ.get(name)
            os.environ[name] = value

    def tearDown(self):
        for name, value in self.saved_env.items():
            os.environ.pop(name)
            if value is not None:
                os.environ[name] = value

    def test_get_from_env(self):
        result = get_from_env()
        self.assertEqual(result['database_url'], self.env_to_set['DATABASE_URL'])
        self.assertEqual(result['auth_url'], self.env_to_set['AUTH_URL'])
        self.assertEqual(result['admin_role'], self.env_to_set['ADMIN_ROLE'])
        self.assertIn('signature_key', result)
