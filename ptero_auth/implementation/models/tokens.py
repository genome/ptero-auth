from .base import Base
from .util import generate_id
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import column_property, relationship
import datetime


__all__ = [ 'RefreshToken' ]


class RefreshToken(Base):
    __tablename__ = 'refresh_token'

    refresh_token_pk = Column(Integer, primary_key=True)

    token = Column(Text, index=True, nullable=False, unique=True)

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

    scopes = relationship('Scope', secondary='refresh_token_scope_bridge')

