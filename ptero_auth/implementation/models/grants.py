from .base import Base
from .util import generate_id
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship
import datetime


__all__ = [ 'AuthorizationCodeGrant'  ]


class AuthorizationCodeGrant(Base):
    __tablename__ = 'authorization_code_grant'
    grant_pk = Column(Integer, primary_key=True)

    created_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=datetime.datetime.utcnow)

    client_pk = Column(Integer, ForeignKey('client.client_pk'), nullable=False)
    user_pk = Column(Integer, ForeignKey('user.user_pk'), nullable=False)

    client = relationship('Client')
    user = relationship('User')

    scopes = relationship('Scope', secondary='grant_scope_bridge')

    code = Column(Text, index=True, nullable=False, unique=True,
            default=lambda: generate_id('ac'))
