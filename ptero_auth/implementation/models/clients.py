from .base import Base
from .scopes import Scope
from .util import generate_id
from Crypto.PublicKey import RSA
from ptero_auth.utils import safe_compare
from sqlalchemy import Column, UniqueConstraint
from sqlalchemy import Boolean, Enum, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import backref, relationship
import datetime
import re
import time


__all__ = [
    'AudienceClaim',
    'ConfidentialClient',
    'EncryptionKey',
    'PublicClient',
]


class ClientInterface(object):
    def is_valid_scope_set(self, scope_set):  # pragma: no cover
        return NotImplemented

    def is_valid_redirect_uri(self, redirect_uri):  # pragma: no cover
        return NotImplemented

    def is_valid_response_type(self, response_type):  # pragma: no cover
        return NotImplemented

    def get_default_redirect_uri(self):  # pragma: no cover
        return NotImplemented


class ConfidentialClient(Base, ClientInterface):
    __tablename__ = 'confidential_client'

    client_pk = Column(Integer, primary_key=True)
    client_id = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: generate_id('ci'))
    client_name = Column(Text, index=True)
    client_secret = Column(Text, default=lambda: generate_id('cs'))

    redirect_uri_regex = Column(Text, nullable=False)
    default_redirect_uri = Column(Text, nullable=False)

    active = Column(Boolean, index=True, default=True)

    created_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=datetime.datetime.utcnow)
    created_by_pk = Column(Integer, ForeignKey('user.user_pk'), nullable=False)
    created_by = relationship('User', foreign_keys=[created_by_pk])

    deactivated_at = Column(DateTime(timezone=True), index=True)
    deactivated_by_pk = Column(Integer, ForeignKey('user.user_pk'))
    deactivated_by = relationship('User', foreign_keys=[deactivated_by_pk])

    allowed_scopes = relationship('Scope', secondary='allowed_scope_bridge')
    default_scopes = relationship('Scope', secondary='default_scope_bridge')

    audience_for_pk = Column(Integer, ForeignKey('scope.scope_pk'), unique=True,
            index=True)
    audience_for = relationship('Scope',
            backref=backref('audience', uselist=False))

    requires_authentication = True
    requires_id_token_encryption = False

    def is_valid_scope_set(self, scope_set):
        return scope_set.issubset(self.allowed_scope_set)

    @property
    def allowed_scope_set(self):
        return set(s.value for s in self.allowed_scopes)

    @property
    def default_scope_set(self):
        return set(s.value for s in self.default_scopes)

    @property
    def as_dict(self):
        result = {
            'active': self.active,
            'allowed_scopes': sorted([s.value for s in self.allowed_scopes]),
            'client_id': self.client_id,
            'created_at': int(time.mktime(self.created_at.utctimetuple())),
            'created_by': self.created_by.name,
            'default_scopes': sorted([s.value for s in self.default_scopes]),
            'default_redirect_uri': self.default_redirect_uri,
            'name': self.client_name,
            'redirect_uri_regex': self.redirect_uri_regex,
        }

        if self.audience_for:
            result['audience_for'] = self.audience_for.value
            if self.audience_claims:
                result['audience_claims'] = [af.value
                        for af in self.audience_claims]

        if self.public_key:
            result['public_key'] = self.public_key.as_dict

        return result

    def authenticate(self, client_secret=None):
        return (self.active and safe_compare(self.client_secret, client_secret))

    _VALID_GRANT_TYPES = set([
        'authorization_code',
        'client_credentials',
        'refresh_token',
    ])
    def is_valid_grant_type(self, grant_type):
        return grant_type in self._VALID_GRANT_TYPES

    def is_valid_response_type(self, response_type):
        return response_type == 'code'

    def is_valid_redirect_uri(self, redirect_uri):
        return re.match(self.redirect_uri_regex, redirect_uri)

    def get_default_redirect_uri(self):
        return self.default_redirect_uri


class AudienceClaim(Base):
    __tablename__ = 'audience_claim'

    audience_claim_pk = Column(Integer, primary_key=True)
    client_pk = Column(Integer, ForeignKey('confidential_client.client_pk'),
            nullable=False)
    value = Column(Enum('posix', 'roles', name='claim_enum'), nullable=False)

    client = relationship(ConfidentialClient, backref='audience_claims')

    __table_args__ = (
        UniqueConstraint('client_pk', 'value', name='_c_af_unique'),
    )


class EncryptionKey(Base):
    __tablename__ = 'encryption_key'

    encryption_key_pk = Column(Integer, primary_key=True)
    client_pk = Column(Integer, ForeignKey('confidential_client.client_pk'),
            nullable=False)
    client = relationship(ConfidentialClient,
            backref=backref('public_key', uselist=False))

    kid = Column(Text, nullable=False, unique=True)
    key = Column(Text, nullable=False)
    alg = Column(Enum('RSA1_5', name='encryption_alg_enum'), nullable=False)
    enc = Column(Enum('A128CBC-HS256', name='encrryption_enc_enum'),
            nullable=False)

    @property
    def as_dict(self):
        return {
            'kid': self.kid,
            'key': self.key,
            'alg': self.alg,
            'enc': self.enc,
        }

    def jot_encrypt_args(self):
        return {
            'kid': self.kid,
            'key': RSA.importKey(self.key),
            'alg': self.alg,
            'enc': self.enc,
        }


class PublicClient(ClientInterface):
    requires_authentication = False
    requires_id_token_encryption = True

    def __init__(self, client_id, session, scopes):
        self.client_id = client_id
        self.session = session
        self.scopes = scopes
        self._audience_client = None

    def is_valid_scope_set(self, scope_set):
        if len(scope_set) not in (1, 2):
            return False

        if len(scope_set) == 2:
            if 'openid' not in scope_set:
                return False

        if not self.get_audience_client():
            return False

        return True

    def get_audience_client(self):
        if not self._audience_client:
            self._audience_client = self.session.query(ConfidentialClient
                    ).join(ConfidentialClient.audience_for
                    ).filter(Scope.value==self._get_audience_scope()
                    ).first()
        return self._audience_client

    def _get_audience_scope(self):
        s = set(self.scopes)
        s.discard('openid')
        if len(s) != 1:
            return
        return s.pop()

    def is_valid_redirect_uri(self, redirect_uri):
        ac = self.get_audience_client()
        if not ac:
            return False
        return ac.is_valid_redirect_uri(redirect_uri)

    _VALID_RESPONSE_TYPES = set([
        'token',
        'id_token token',
        'token id_token',
    ])
    def is_valid_response_type(self, response_type):
        return response_type in self._VALID_RESPONSE_TYPES

    def get_default_redirect_uri(self):
        ac = self.get_audience_client()
        if not ac:
            return None
        return ac.get_default_redirect_uri()
