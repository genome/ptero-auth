from ..base import Base
from ..util import generate_id
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship
import datetime


__all__ = [
    'AuthorizationCodeGrant',
    'ClientCredentialsGrant',
    'Grant',
    'ImplicitGrant',
]


class Grant(Base):
    __tablename__ = 'grant'
    __mapper_args__ = {
        'polymorphic_on': 'grant_type',
    }
    grant_pk = Column(Integer, primary_key=True)
    grant_type = Column(Text, index=True, nullable=False)

    created_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=datetime.datetime.utcnow)

    client_pk = Column(Integer, ForeignKey('client.client_pk'), nullable=False)
    user_pk = Column(Integer, ForeignKey('user.user_pk'), nullable=False)

    client = relationship('Client')
    user = relationship('User')

    @property
    def active(self):
        return NotImplemented

    @property
    def deactivated_at(self):
        return NotImplemented


class AuthorizationCodeGrant(Grant):
    __tablename__ = 'authorization_code_grant'
    __mapper_args__ = {
        'polymorphic_identity': 'authorization_code',
    }

    grant_pk = Column(Integer, ForeignKey('grant.grant_pk'), primary_key=True)

    code = Column(Text, index=True, nullable=False, unique=True,
            default=lambda: generate_id('ac'))

    active = Column(Boolean, nullable=False, default=False)
    deactivated_at = Column(DateTime(timezone=True), index=True)


class ClientCredentialsGrant(Grant):
    __tablename__ = 'client_credentials_grant'
    __mapper_args__ = {
        'polymorphic_identity': 'client_credentials',
    }

    grant_pk = Column(Integer, ForeignKey('grant.grant_pk'), primary_key=True)

    @property
    def active(self):
        return False

    @property
    def deactivated_at(self):
        return self.created_at


class ImplicitGrant(Grant):
    __tablename__ = 'implicit_grant'
    __mapper_args__ = {
        'polymorphic_identity': 'implicit',
    }

    grant_pk = Column(Integer, ForeignKey('grant.grant_pk'), primary_key=True)

    @property
    def active(self):
        return False

    @property
    def deactivated_at(self):
        return self.created_at
