from .server import OIDCServer
from .token_handler import OIDCTokenHandler
from .validator import OIDCRequestValidator


__all__ = ['create_server']


def create_server(db_session, signature_key):
    validator = OIDCRequestValidator(db_session)
    token_handler = OIDCTokenHandler(validator, **signature_key)
    return OIDCServer(validator, token_handler)
