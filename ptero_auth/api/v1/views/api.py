from . import common
from ptero_auth import exceptions
from flask import g, request, url_for
from flask.ext.restful import Resource
import logging


__all__ = ['ApiKeyListView', 'ApiKeyView']


class ApiKeyListView(Resource):
    def post(self):
        user = g.backend.get_user_from_authorization(request.authorization)
        if not user:
            return common.require_authorization()

        # XXX Invalidate other api keys?
        api_key = g.backend.create_api_key_for_user(user)

        return api_key.as_dict, 201, {
                'Location': url_for('api-key', api_key=api_key.key),
        }


class ApiKeyView(Resource):
    def get(self, api_key):
        user = g.backend.get_user_from_authorization(request.authorization)
        if not user:
            return common.require_authorization()

        key = g.backend.get_api_key(api_key)
        if not key:
            return None, 404

        if key.user != user:
            return None, 404

    def patch(self, api_key):
        pass
