from .base import Base
from .util import generate_id
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy import func
from sqlalchemy.orm import relationship
import datetime
import grp
import os
import pwd
import simplepam
import sqlalchemy


__all__ = ['Key', 'User']


class User(Base):
    __tablename__ = 'user'

    user_pk = Column(Integer, primary_key=True)
    name = Column(Text, index=True, nullable=False, unique=True)
    oidc_sub = Column(Text, nullable=False, unique=True,
            default=lambda: generate_id('sub'))
    banned = Column(Boolean, index=True, nullable=False, default=False)

    @classmethod
    def create_or_get(cls, session, username):
        user = User(name=username)
        session.add(user)
        try:
            session.commit()

        except sqlalchemy.exc.IntegrityError:
            session.rollback()
            user = session.query(User).filter_by(name=username).one()

        return user

    @property
    def details(self):
        return {
            'name': name,
            'uid': self.uid,
            'gid': self.gid,
            'groups': self.groups,
            'roles': self.roles,
        }

    @property
    def uid(self):
        pw_struct = pwd.getpwnam(self.name)
        return pw_struct.pw_uid

    @property
    def gid(self):
        pw_struct = pwd.getpwnam(self.name)
        return pw_struct.pw_gid

    @property
    def groups(self):
        return [self.gid] + [g.gr_gid for g in grp.getgrall()
                             if self.name in g.gr_mem]

    @property
    def roles(self):
        return self.groups

    def validate_password(self, password):
        return simplepam.authenticate(self.name, password)


class Key(Base):
    __tablename__ = 'api_key'

    key_id = Column(Integer, primary_key=True)
    key = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: generate_id('k'))
    user_pk = Column(Integer, ForeignKey('user.user_pk'), nullable=False)

    active = Column(Boolean, default=True)
    deactivated_at = Column(DateTime(timezone=True), index=True)
    created_at = Column(DateTime(timezone=True), index=True, nullable=False,
            default=datetime.datetime.utcnow)

    usage_count = Column(Integer, index=True, default=0)
    last_used = Column(DateTime(timezone=True), index=True)

    user = relationship(User)

    @property
    def as_dict(self):
        return {
            'api-key': self.key,
        }