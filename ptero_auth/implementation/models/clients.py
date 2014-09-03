from .base import Base
from .scopes import Scope
from .util import generate_id
from ptero_auth.utils import safe_compare
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship
import datetime
import re
import time


__all__ = ['ConfidentialClient', 'PublicClient']


class ConfidentialClient(Base):
    __tablename__ = 'confidential_client'

    client_pk = Column(Integer, primary_key=True)
    client_id = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: generate_id('ci'))
    client_name = Column(Text, index=True)
    client_secret = Column(Text, default=lambda: generate_id('cs'))

    redirect_uri_regex = Column(Text, nullable=False)

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

    requires_authentication = True

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
            'name': self.client_name,
            'redirect_uri_regex': self.redirect_uri_regex,
        }

        if self.audience_for:
            result['audience_for'] = self.audience_for.value

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

    def is_valid_redirect_uri(self, redirect_uri, scopes=None):
        return re.match(self.redirect_uri_regex, redirect_uri)


class PublicClient(object):
    requires_authentication = False

    def __init__(self, client_id, session):
        self.client_id = client_id
        self.session = session
        self._audience_client = None

    def is_valid_scope_set(self, scopes):
        if len(scopes) not in (1, 2):
            return False

        if len(scopes) == 2:
            if 'openid' not in scopes:
                return False

        if not self._get_audience_client(scopes):
            return False

        return True

    def _get_audience_client(self, scopes):
        if not self._audience_client:
            self._audience_client = self.session.query(ConfidentialClient
                    ).join(ConfidentialClient.audience_for
                    ).filter(Scope.value==self._get_audience_scope(scopes)
                    ).first()
        return self._audience_client

    def _get_audience_scope(self, scopes):
        s = set(scopes)
        s.discard('openid')
        if not s:
            return
        return s.pop()

    def is_valid_redirect_uri(self, redirect_uri, scopes):
        ac = self._get_audience_client(scopes)
        if not ac:
            return False
        return ac.is_valid_redirect_uri(redirect_uri, scopes)

    _VALID_RESPONSE_TYPES = set([
        'token',
        'id_token token',
        'token id_token',
    ])
    def is_valid_response_type(self, response_type):
        return response_type in self._VALID_RESPONSE_TYPES
