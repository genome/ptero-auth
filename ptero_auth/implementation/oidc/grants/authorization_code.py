from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant


class OIDCAuthorizationCodeGrant(AuthorizationCodeGrant):
    def __init__(self, request_validator, token_handler):
        AuthorizationCodeGrant.__init__(self, request_validator)
        self._oidc_token_handler = token_handler

    def create_token_response(self, request, token_handler):
        return AuthorizationCodeGrant.create_token_response(self,
                request, self._oidc_token_handler)
