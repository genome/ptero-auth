from ptero_auth import exceptions
from flask import g, request
from flask.ext.restful import Resource
import logging
import urllib


__all__ = ['AuthorizeView', 'TokenView']


LOG = logging.getLogger(__file__)


class AuthorizeView(Resource):
    def get(self):
        return self._unauthorized_response()

    def post(self):
        try:
            api_key = self._get_api_key()
        except exceptions.NoApiKey:
            return self._unauthorized_response()

        scopes = self._get_scopes()

        return g.oidc_server.create_authorization_response(uri=request.url,
                headers=request.headers, scopes=scopes,
                credentials={'api_key': api_key})

    def _unauthorized_response(self):
        # XXX Make sure to set the 'WWW-Authenticate' header based on oidc
        # interaction settings (e.g. none, only add a WWW-Authenitcate header
        # for api keys).
        return '', 401, {'Location': request.url}

    def _get_api_key(self):
        authorization = request.headers['Authorization']
        if not authorization or not authorization.startswith('Bearer '):
            raise exceptions.NoApiKey()

        return authorization[8:]

    def _get_scopes(self):
        scope = request.args['scope']
        if not scope:
            return []

        else:
            return scope.split(' ')


class TokenView(Resource):
    def post(self):
        regenerated_body = urllib.urlencode(request.form)

        headers, body, status_code = g.oidc_server.create_token_response(
                uri=request.url, headers=request.headers, body=regenerated_body)

        return body, status_code, headers
