from .grants import OIDCAuthorizationCodeGrant, OIDCImplicitGrant
from oauthlib.oauth2.rfc6749.endpoints import AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.endpoints import TokenEndpoint
from oauthlib.oauth2.rfc6749.grant_types import ImplicitGrant
from oauthlib.oauth2.rfc6749.grant_types import RefreshTokenGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken


__all__ = ['OIDCServer']


class OIDCServer(AuthorizationEndpoint, TokenEndpoint):
    def __init__(self, request_validator, oidc_token_handler):
        implicit_grant = ImplicitGrant(request_validator)
        refresh_grant = RefreshTokenGrant(request_validator)
        oidc_code_grant = OIDCAuthorizationCodeGrant(request_validator,
                oidc_token_handler)
        oidc_implicit_grant = OIDCImplicitGrant(request_validator,
                oidc_token_handler)

        bearer_token_handler = BearerToken(request_validator)

        AuthorizationEndpoint.__init__(self,
                default_response_type=oidc_code_grant,
                default_token_type=bearer_token_handler,
                response_types={
                    'code': oidc_code_grant,
                    'token': implicit_grant,

                    'id_token token': oidc_implicit_grant,
                    'token id_token': oidc_implicit_grant,
                })

        TokenEndpoint.__init__(self,
                default_grant_type=oidc_code_grant,
                default_token_type=bearer_token_handler,
                grant_types={
                    'authorization_code': oidc_code_grant,
                    'refresh_token': refresh_grant,
                })
