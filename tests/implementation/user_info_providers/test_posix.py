from ptero_auth.implementation.user_info_providers import posix
import os
import unittest


@unittest.skipUnless(os.environ.get('TEST_POSIX_PROVIDER'),
        'TEST_POSIX_PROVIDER not set')
class PosixUserInfoProviderTest(unittest.TestCase):
    VALID_LOGIN_PAIRS = [
        ('alice', 'apass'),
        ('bob', 'foobob'),
        ('charlie', 'charles'),
    ]
    def test_check_login_success(self):
        for username, password in self.VALID_LOGIN_PAIRS:
            self.assertTrue(posix.check_login(username, password))

    def test_check_login_invalid_password(self):
        self.assertFalse(posix.check_login('alice', 'nogood'))

    def test_check_login_invalid_user(self):
        self.assertFalse(posix.check_login('notaperson', 'anypass'))
