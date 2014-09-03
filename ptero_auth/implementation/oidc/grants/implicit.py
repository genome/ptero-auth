from oauthlib import common
from oauthlib.common import log
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import ImplicitGrant
from oauthlib.uri_validate import is_absolute_uri


class OIDCImplicitGrant(ImplicitGrant):
    VALID_RESPONSE_TYPES = {'token', 'id_token token'}

    def __init__(self, request_validator, token_handler):
        ImplicitGrant.__init__(self, request_validator)
        self._oidc_token_handler = token_handler

    def create_token_response(self, request, token_handler):
        return ImplicitGrant.create_token_response(self, request,
                self._oidc_token_handler)

# XXX validate_token_request asserts that response_type == 'token', which is
#     not true in OIDC (it could also be 'token id_token' or 'id_token token')
    def validate_token_request(self, request):
        """Check the token request for normal and fatal errors.

        This method is very similar to validate_authorization_request in
        the AuthorizationCodeGrant but differ in a few subtle areas.

        A normal error could be a missing response_type parameter or the client
        attempting to access scope it is not allowed to ask authorization for.
        Normal errors can safely be included in the redirection URI and
        sent back to the client.

        Fatal errors occur when the client_id or redirect_uri is invalid or
        missing. These must be caught by the provider and handled, how this
        is done is outside of the scope of OAuthLib but showing an error
        page describing the issue is a good idea.
        """

        # First check for fatal errors

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.

        # REQUIRED. The client identifier as described in Section 2.2.
        # http://tools.ietf.org/html/rfc6749#section-2.2
        if not request.client_id:
            raise errors.MissingClientIdError(state=request.state, request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(state=request.state, request=request)

        # OPTIONAL. As described in Section 3.1.2.
        # http://tools.ietf.org/html/rfc6749#section-3.1.2
        if request.redirect_uri is not None:
            request.using_default_redirect_uri = False
            log.debug('Using provided redirect_uri %s', request.redirect_uri)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(state=request.state, request=request)

            # The authorization server MUST verify that the redirection URI
            # to which it will redirect the access token matches a
            # redirection URI registered by the client as described in
            # Section 3.1.2.
            # http://tools.ietf.org/html/rfc6749#section-3.1.2
            if not self.request_validator.validate_redirect_uri(
                    request.client_id, request.redirect_uri, request):
                raise errors.MismatchingRedirectURIError(state=request.state, request=request)
        else:
            request.redirect_uri = self.request_validator.get_default_redirect_uri(
                    request.client_id, request)
            request.using_default_redirect_uri = True
            log.debug('Using default redirect_uri %s.', request.redirect_uri)
            if not request.redirect_uri:
                raise errors.MissingRedirectURIError(state=request.state, request=request)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(state=request.state, request=request)

        # Then check for normal errors.

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the fragment component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B.
        # http://tools.ietf.org/html/rfc6749#appendix-B

        # Note that the correct parameters to be added are automatically
        # populated through the use of specific exceptions.
        if request.response_type is None:
            raise errors.InvalidRequestError(state=request.state,
                    description='Missing response_type parameter.',
                    request=request)

        for param in ('client_id', 'response_type', 'redirect_uri', 'scope', 'state'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(state=request.state,
                        description='Duplicate %s parameter.' % param, request=request)

        # REQUIRED. Value MUST be set to "token".
        if request.response_type not in self.VALID_RESPONSE_TYPES:
            raise errors.UnsupportedResponseTypeError(state=request.state, request=request)

        log.debug('Validating use of response_type token for client %r (%r).',
                  request.client_id, request.client)
        if not self.request_validator.validate_response_type(request.client_id,
                request.response_type, request.client, request):
            log.debug('Client %s is not authorized to use response_type %s.',
                      request.client_id, request.response_type)
            raise errors.UnauthorizedClientError(request=request)

        # OPTIONAL. The scope of the access request as described by Section 3.3
        # http://tools.ietf.org/html/rfc6749#section-3.3
        self.validate_scopes(request)

        return request.scopes, {
                'client_id': request.client_id,
                'redirect_uri': request.redirect_uri,
                'response_type': request.response_type,
                'state': request.state,
                'request': request,
        }
