from .. import models
from oauthlib.oauth2 import RequestValidator
from ptero_auth.utils import safe_compare


class OIDCRequestValidator(RequestValidator):
    def __init__(self, session):
        self.session = session

    def _get_client(self, client_id):
        return self.session.query(models.Client
                ).filter_by(client_id=client_id).first()

    def validate_client_id(self, client_id, request):
        request.client = self._get_client(client_id)
        return request.client is not None

    def validate_redirect_uri(self, client_id, redirect_uri, request):
        return request.client.is_valid_redirect_uri(redirect_uri)

    def validate_scopes(self, client_id, scopes, client, request):
        return client.is_valid_scope_set(set(scopes))

    def validate_response_type(self, client_id, response_type, client, request):
        return client.is_valid_response_type(response_type)

    def save_authorization_code(self, client_id, code, request):
        ac = models.AuthorizationCodeGrant(code=code['code'],
                user=request.user, client=request.client,
                redirect_uri=request.redirect_uri)
        ac.scopes = self.session.query(models.Scope
                ).filter(models.Scope.value.in_(request.scopes)).all()
        self.session.add(ac)
        self.session.commit()

    def client_authentication_required(self, request):
        request.client = self._get_client(self._get_client_id(request))
        return request.client.requires_authentication

    def _get_client_id(self, request):
        auth = request.extra_credentials.get('flask-auth')
        if auth and hasattr(auth, 'username'):
            return auth.username

    def _get_client_secret(self, request):
        auth = request.extra_credentials.get('flask-auth')
        if auth and hasattr(auth, 'password'):
            return auth.password

    def authenticate_client(self, request):
        return request.client.authenticate(self._get_client_secret(request))

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
        ac = self.session.query(models.AuthorizationCodeGrant).filter_by(
                code=code, client=client).first()
        if ac:
            return ac.redirect_uri == redirect_uri

    def save_bearer_token(self, token, request):
        if 'refresh_token' in token:
            r = models.RefreshToken(token=token.get('refresh_token'),
                    user=request.user, client=request.client)
            self.session.add(r)
            self.session.commit()

    def invalidate_authorization_code(self, client_id, code, request):
        self.session.query(models.AuthorizationCodeGrant
                ).filter_by(code=code).delete()
        self.session.commit()

    def get_default_redirect_uri(self, client_id, request):
        return 'http://error.com/bad/library'
