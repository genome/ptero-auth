from .base import Base
from .util import generate_id
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import column_property, relationship
import datetime


__all__ = [
    'AccessToken',
    'RefreshableAccessToken',
    'RefreshToken',
    'SingletonAccessToken',
]


class RefreshToken(Base):
    __tablename__ = 'refresh_token'

    refresh_token_pk = Column(Integer, primary_key=True)

    created_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=datetime.datetime.utcnow)
    expires_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=lambda: datetime.datetime.utcnow()
                + datetime.timedelta(days=30))

    client_pk = Column(Integer, ForeignKey('client.client_pk'), nullable=False)
    user_pk = Column(Integer, ForeignKey('user.user_pk'), nullable=False)

    client = relationship('Client')
    user = relationship('User')

    active = Column(Boolean, nullable=False, default=False)
    deactivated_at = Column(DateTime(timezone=True), index=True)

    grant_pk = Column(Integer, ForeignKey('authorization_code_grant.grant_pk'), nullable=False)

    grant = relationship('AuthorizationCodeGrant')


class AccessToken(Base):
    __tablename__ = 'access_token'
    __mapper_args__ = {
        'polymorphic_on': 'access_token_type',
    }
    access_token_pk = Column(Integer, primary_key=True)
    access_token_type = Column(Text, index=True, nullable=False)
    token = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: generate_id('at'))

    created_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=datetime.datetime.utcnow)
    expires_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=lambda: datetime.datetime.utcnow()
                + datetime.timedelta(minutes=10))

    active = Column(Boolean, nullable=False, default=False)
    deactivated_at = Column(DateTime(timezone=True), index=True)

    @property
    def client(self):
        return self.grant.client

    @property
    def user(self):
        return self.grant.user


class RefreshableAccessToken(AccessToken):
    __tablename__ = 'refreshable_access_token'
    __mapper_args__ = {
        'polymorphic_identity': 'refreshable',
    }

    access_token_pk = Column(Integer,
            ForeignKey('access_token.access_token_pk'), primary_key=True)

    refresh_token_id = Column(Integer,
            ForeignKey('refresh_token.refresh_token_pk'),
            nullable=False)

    @property
    def grant(self):
        return self.refresh_token.grant


class SingletonAccessToken(AccessToken):
    __tablename__ = 'singleton_access_token'
    __mapper_args__ = {
        'polymorphic_identity': 'singleton',
    }

    access_token_pk = Column(Integer,
            ForeignKey('access_token.access_token_pk'), primary_key=True)
