from ..base import Base
from ..util import generate_id
from sqlalchemy import Column, ForeignKey, Integer, Text
from sqlalchemy import Table, PrimaryKeyConstraint
from sqlalchemy.orm import relationship


__all__ = ['Scope']


class Scope(Base):
    __tablename__ = 'scope'

    scope_pk = Column(Integer, primary_key=True)
    value = Column(Text, index=True, unique=True, nullable=False)

    audience = relationship('Client', secondary='scope_audience_bridge',
            backref='audience_for')


allowed_scope_table = Table('allowed_scope_bridge', Base.metadata,
    Column('client_pk', Integer, ForeignKey('client.client_pk')),
    Column('scope_pk', Integer, ForeignKey('scope.scope_pk')),
    PrimaryKeyConstraint('client_pk', 'scope_pk')
)


default_scope_table = Table('default_scope_bridge', Base.metadata,
    Column('client_pk', Integer, ForeignKey('client.client_pk')),
    Column('scope_pk', Integer, ForeignKey('scope.scope_pk')),
    PrimaryKeyConstraint('client_pk', 'scope_pk')
)


scope_audience_table = Table('scope_audience_bridge', Base.metadata,
    Column('client_pk', Integer, ForeignKey('client.client_pk')),
    Column('scope_pk', Integer, ForeignKey('scope.scope_pk')),
    PrimaryKeyConstraint('client_pk', 'scope_pk')
)


grant_scope_table = Table('grant_scope_bridge', Base.metadata,
    Column('grant_pk', Integer, ForeignKey('grant.grant_pk')),
    Column('scope_pk', Integer, ForeignKey('scope.scope_pk')),
    PrimaryKeyConstraint('grant_pk', 'scope_pk')
)
