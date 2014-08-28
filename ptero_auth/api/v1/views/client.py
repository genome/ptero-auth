from . import common
from ptero_auth import exceptions
from flask import g, request
from flask.ext.restful import Resource
import json
import logging


__all__ = ['ClientListView', 'ClientView']


class ClientListView(Resource):
    def get(self):
        pass

    def post(self):
        user = g.backend.get_user_from_authorization(request.authorization)
        if not user:
            return common.require_authorization()

        if not g.backend.is_user_admin(user):
            return None, 403

        client_data = g.backend.register_client(json.loads(request.data))

        return client_data, 201


class ClientView(Resource):
    def get(self, client_id):
        pass

    def patch(self, client_id):
        pass
