from . import common
from ptero_auth import exceptions
from flask import g, request
from flask.ext.restful import Resource
import logging
import urllib


__all__ = ['AuthorizeView', 'TokenView']


LOG = logging.getLogger(__file__)


class AuthorizeView(Resource):
    def get(self):
        try:
            api_key = self._get_api_key()
        except exceptions.NoApiKey:
            return common.require_authorization('API-Key')

        user = g.backend.get_user_from_api_key(api_key)
        if not user:
            return None, 403

        scopes = self._get_scopes()

        header, body, status_code = g.backend.oidc_server.create_authorization_response(
                uri=request.url, headers=request.headers, scopes=scopes,
                credentials={'user': user})

        return body, status_code, header

    def _get_api_key(self):
        authorization = request.headers.get('Authorization')
        if not authorization or not authorization.startswith('API-Key '):
            raise exceptions.NoApiKey()

        return authorization[8:]

    def _get_scopes(self):
        scope = request.args.get('scope')
        if not scope:
            return self._get_default_scopes()

        else:
            return scope.split(' ')

    def _get_default_scopes(self):
        client = g.backend.get_client(request.args.get('client_id'))
        return client['default_scopes']


class TokenView(Resource):
    def post(self):
        header, body, status_code = g.backend.oidc_server.create_token_response(
                uri=request.url, headers=request.headers, body=request.data,
                credentials={'flask-auth': request.authorization})

        return body, status_code, header
