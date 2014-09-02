from flask.ext.restful import Api
from . import views


__all__ = ['api']


api = Api(default_mediatype='application/json')

# OAuth 2.0 Endpoints
api.add_resource(views.AuthorizeView, '/authorize', endpoint='authorize')
api.add_resource(views.TokenView, '/tokens', endpoint='tokens')

# Application-specific endpoints
api.add_resource(views.ApiKeyListView, '/api-keys', endpoint='api-key-list')
api.add_resource(views.ApiKeyView, '/api-keys/<string:api_key>',
        endpoint='api-key')
api.add_resource(views.ClientListView, '/clients', endpoint='client-list')
api.add_resource(views.ClientView, '/clients/<string:client_id>',
        endpoint='client')
api.add_resource(views.UserListView, '/users', endpoint='user-list')
api.add_resource(views.UserView, '/users/<string:user_name>', endpoint='user')
