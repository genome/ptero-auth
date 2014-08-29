from .base import BaseFlaskTest
import json


class GetAuthorize(BaseFlaskTest):
    def test_should_return_401_with_no_api_key(self):
        response = self.client.get('/v1/authorize')

        self.assertEqual(response.status_code, 401)

    def test_should_return_www_authenticate_header_with_no_api_key(self):
        response = self.client.get('/v1/authorize')

        self.assertEqual(response.headers['WWW-Authenticate'], 'API-Key')
