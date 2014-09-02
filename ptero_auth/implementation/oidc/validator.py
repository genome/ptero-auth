from .. import models
from oauthlib.oauth2 import RequestValidator
from ptero_auth.utils import safe_compare


class OIDCRequestValidator(RequestValidator):
    # XXX Some of these methods are supposed to modify the request, attaching
    #     data like user or client.

    def __init__(self, session):
        self.session = session

    def _get_client(self, client_id):
        return self.session.query(models.Client
                ).filter_by(client_id=client_id).first()

    def _get_key(self, request):
        return self.session.query(models.Key
                ).filter_by(key=request.headers['Authorization'][8:]).one()

    def validate_client_id(self, client_id, request):
        request.client = self._get_client(client_id)
        return request.client is not None

    def validate_redirect_uri(self, client_id, redirect_uri, request):
        # XXX Needed
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        return True

    def validate_scopes(self, client_id, scopes, client, request):
        c = self._get_client(client_id)

        return c.is_valid_scope_set(set(scopes))

    def get_default_scopes(self, client_id, request):
        return self._get_client(client_id).default_scopes

    def validate_response_type(self, client_id, response_type, client, request):
        c = self._get_client(client_id)
        return c.is_valid_response_type(response_type)

    def save_authorization_code(self, client_id, code, request):
        ac = models.AuthorizationCodeGrant(code=code['code'],
                user=request.user, client=self._get_client(client_id))
        ac.scopes = self.session.query(models.Scope
                ).filter(models.Scope.value.in_(request.scopes)).all()
        self.session.add(ac)
        self.session.commit()

    def client_authentication_required(self, request):
        request.client = self._get_client(self._get_client_id(request))
        return request.client.requires_authentication

    def _get_client_id(self, request):
        if request.client_id:
            return request.client_id

        else:
            auth = request.extra_credentials.get('flask-auth')
            if auth and hasattr(auth, 'username'):
                request.client_id = auth.username
                return auth.username

    def _get_client_secret(self, request):
        if request.client_secret:
            return request.client_secret

        else:
            auth = request.extra_credentials.get('flask-auth')
            if auth and hasattr(auth, 'password'):
                request.client_secret = auth.password
                return auth.password

    def authenticate_client(self, request):
        c = self._get_client(request.client_id)
        if safe_compare(request.client_secret, c.client_secret):
            request.client = c
            return True

    def authenticate_client(self, request):
        client_secret = self._get_client_secret(request)
        return client_secret == request.client.client_secret

    def validate_grant_type(self, client_id, grant_type, client, request):
        return client.is_valid_grant_type(grant_type)

    def validate_code(self, client_id, code, client, request):
        ac = self.session.query(models.AuthorizationCodeGrant).filter_by(
                code=code, client=client).first()
        if ac:
            request.user = ac.user
            request.scopes = [ s.value for s in ac.scopes ]
            return True
        else:
            return False

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client):
        # XXX Should be picky, maybe each client registers a regex?
        return True

    def save_bearer_token(self, token, request):
        if 'refresh_token' in token:
            r = models.RefreshToken(token=token.get('refresh_token'),
                    user=request.user, client=request.client)
            self.session.add(r)
            self.session.commit()

    def invalidate_authorization_code(self, client_id, code, request):
        # XXX Should flag the code as inactive/invalid
        pass
