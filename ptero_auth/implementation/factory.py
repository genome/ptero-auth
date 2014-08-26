from . import backend
from . import models
import sqlalchemy


__all__ = ['Factory']


class Factory(object):
    def __init__(self, settings):
        self.settings = settings
        self._initialized = False
        self._engine = None
        self._Session = None

    def create_backend(self):
        self._initialize()
        return backend.Backend(self._Session(), self.settings['signature_key'])

    def _initialize(self):
        # Lazy initialize to be pre-fork friendly.
        if not self._initialized:
            self._initialize_sqlalchemy()
            self._initialized = True

    def _initialize_sqlalchemy(self):
        self._engine = sqlalchemy.create_engine(self.settings['database_url'])
        models.Base.metadata.create_all(self._engine)
        self._Session = sqlalchemy.orm.sessionmaker(bind=self._engine)