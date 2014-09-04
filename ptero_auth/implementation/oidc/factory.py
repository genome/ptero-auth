from .server import OIDCServer
from .token_handler import OIDCTokenHandler
from .validator import OIDCRequestValidator


__all__ = ['create_server']


def create_server(db_session, user_info_provider, signature_key):
    validator = OIDCRequestValidator(db_session)
    token_handler = OIDCTokenHandler(validator, db_session, user_info_provider,
            **signature_key)
    return OIDCServer(validator, token_handler)
