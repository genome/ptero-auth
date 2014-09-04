from oauthlib.oauth2.rfc6749.tokens import BearerToken
from ptero_auth.implementation import models
import hashlib
import jot
import jot.codec
import datetime
import time
import uuid


_AT_HASH_ALGORITHMS = {
    'HS256': lambda d: hashlib.sha256(d).digest(),
    'RS256': lambda d: hashlib.sha256(d).digest(),
}


class OIDCTokenHandler(BearerToken):
    def __init__(self, request_validator, db_session, user_info_provider,
            signature_alg='HS256', signature_key=None, signature_kid=None,
            namespace=uuid.UUID('66deca4c-4e8a-44ce-a617-3d37bc0bcfaa'),
            *args, **kwargs):
        BearerToken.__init__(self, request_validator, *args, **kwargs)
        self.db_session = db_session
        self.user_info_provider = user_info_provider
        self.namespace = namespace
        self.signature_alg = signature_alg
        self.signature_key = signature_key
        self.signature_kid = signature_kid

    def create_id_token(self, request, bearer_token):
        # NOTE If we're doing implicit, we need to encrypt the token for the
        # intended party.  We could associate encryption keys with each client
        # in the database and fetch the client objects from the
        # request_validator, then get their public keys.

        iat = int(time.mktime(datetime.datetime.utcnow().timetuple()))
        exp = iat + 600
        audiences = self.get_aud(request)
        id_token = jot.Token(claims={
            'iss': 'https://auth.ptero.gsc.wustl.edu',
            'sub': request.user.oidc_sub,
            'aud': [a.client_id for a in audiences],
            'exp': exp,
            'iat': iat,
            'at_hash': self._at_hash(bearer_token['access_token']),
        })

        claim_data = self._get_claim_data(request.user, audiences)
        for claim_name, data in claim_data.iteritems():
            id_token.set_claim_in_namespace(self.namespace, claim_name, data)

        jws = id_token.sign_with(self.signature_key, alg=self.signature_alg,
                kid=self.signature_kid)

        if request.client.requires_id_token_encryption:
            aud_client = request.client.get_audience_client()
            jwe = jws.encrypt_with(**aud_client.public_key.jot_encrypt_args())
            return jwe.compact_serialize()

        else:
            return jws.compact_serialize()

    def create_token(self, request, refresh_token=False):
        token = super(OIDCTokenHandler, self).create_token(request, refresh_token)
        if 'openid' in request.scopes:
            token['id_token'] = self.create_id_token(request, token)
        return token

    def _at_hash(self, access_token):
        hasher = _AT_HASH_ALGORITHMS[self.signature_alg]
        digest = hasher(access_token)
        l = len(digest) / 2
        return jot.codec.base64url_encode(digest[:l])

    def get_aud(self, request):
        result = []

        scope_set = set(request.scopes)
        scope_set.discard('openid')
        for scope in scope_set:
            audience = self._get_aud_client(scope)
            if audience:
                result.append(audience)

        return result

    def _get_aud_client(self, scope):
        s_obj = self.db_session.query(models.Scope
                ).filter_by(value=scope).first()
        return s_obj.audience

    def _get_claim_data(self, user, audiences):
        claim_names = set()
        for a in audiences:
            for af in a.audience_claims:
                claim_names.add(str(af.value))
        return self.user_info_provider.get_user_data(user, claim_names)
