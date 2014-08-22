from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from urlparse import urlparse
import logging
import os


LOG = logging.getLogger(__file__)


__all__ = ['get_from_env']


def _get_signature_key():
    private_key = RSA.importKey(os.environ['SIGNATURE_KEY'])

    fingerprint = _calculate_fingerprint(private_key.publickey())
    return {
        'signature_alg': 'RS256',
        'signature_key': private_key,
        'signature_kid': fingerprint,
    }


def _calculate_fingerprint(public_key):
    return SHA256.new(
            public_key.exportKey(format='DER', pkcs=8)).hexdigest()[:8]


def port(AUTH_URL):
    return urlparse(AUTH_URL).port


def get_from_env():
    result = {}

    result['signature_key'] = _get_signature_key()
    result['database_url'] = os.environ['DATABASE_URL']
    result['auth_url'] = os.environ['AUTH_URL']
    result['port'] = port(result['auth_url'])

    return result
