from ptero_auth import exceptions
from flask import request
from flask.ext.restful import Resource
import logging


__all__ = ['UserListView', 'UserView']


class UserListView(Resource):
    def get(self):
        pass


class UserView(Resource):
    def get(self, user_name):
        pass

    def patch(self, user_name):
        pass
