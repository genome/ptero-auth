from ptero_auth import exceptions
from flask import request
from flask.ext.restful import Resource
import logging


__all__ = ['ClientListView', 'ClientView']


class ClientListView(Resource):
    def get(self):
        pass

    def post(self):
        return None, 201


class ClientView(Resource):
    def get(self, client_id):
        pass

    def patch(self, client_id):
        pass
