from .base import Base
from .util import generate_id
from ptero_auth.utils import safe_compare
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship
import datetime
import re
import time


__all__ = ['Client', 'ConfidentialClient', 'PublicClient', 'create_client']


class Client(Base):
    __tablename__ = 'client'
    __mapper_args__ = {
        'polymorphic_on': 'client_type',
    }

    client_pk = Column(Integer, primary_key=True)
    client_id = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: generate_id('ci'))
    client_name = Column(Text, index=True)
    client_type = Column(Text, index=True, nullable=False)

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
    audience_for = relationship('Scope', backref='audience')

    def authenticate(self, client_secret=None):  # pragma: no cover
        return NotImplemented

    @property
    def requires_authentication(self):  # pragma: no cover
        return NotImplemented

    def is_valid_redirect_uri(self, redirect_uri):  # pragma: no cover
        return NotImplemented

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
        return {
            'active': self.active,
            'allowed_scopes': sorted([s.value for s in self.allowed_scopes]),
            'audience_for': self.audience_for.value,
            'client_id': self.client_id,
            'created_at': int(time.mktime(self.created_at.utctimetuple())),
            'created_by': self.created_by.name,
            'default_scopes': sorted([s.value for s in self.default_scopes]),
            'name': self.client_name,
            'type': self.client_type,
        }


class ConfidentialClient(Client):
    __tablename__ = 'confidential_client'
    __mapper_args__ = {
        'polymorphic_identity': 'confidential',
    }

    client_pk = Column(Integer, ForeignKey('client.client_pk'),
            primary_key=True)
    client_secret = Column(Text, default=lambda: generate_id('cs'))

    redirect_uri_regex = Column(Text, nullable=False)

    @property
    def requires_authentication(self):
        return True

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

    @property
    def as_dict(self):
        result = super(ConfidentialClient, self).as_dict
        result['redirect_uri_regex'] = self.redirect_uri_regex
        return result

class PublicClient(Client):
    __tablename__ = 'public_client'
    __mapper_args__ = {
        'polymorphic_identity': 'public',
    }

    client_pk = Column(Integer, ForeignKey('client.client_pk'),
            primary_key=True)

    @property
    def requires_authentication(self):
        return False

    def authenticate(self, client_secret=None):
        return self.active

    def is_valid_redirect_uri(self, redirect_uri):
        return redirect_uri == None

    def is_valid_grant_type(self, grant_type):
        # XXX This should probably raise an exception.
        return False

    _VALID_RESPONSE_TYPES = set([
        'token',
        'id_token token',
        'token id_token',
    ])
    def is_valid_response_type(self, response_type):
        return response_type in self._VALID_RESPONSE_TYPES


_CLIENT_TYPES = {
    'confidential': ConfidentialClient,
    'public': PublicClient,
}
def create_client(client_type=None, redirect_uri_regex=None, **kwargs):
    cls = _CLIENT_TYPES[client_type]
    client = cls(**kwargs)
    if client_type == 'confidential':
        client.redirect_uri_regex = redirect_uri_regex
    return client
