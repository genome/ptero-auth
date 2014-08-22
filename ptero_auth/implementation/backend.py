from .oidc.factory import create_server
from . import models


class Backend(object):
    def __init__(self, session, signature_key):
        self.session = session
        self.oidc_server = create_server(session, signature_key)

    def cleanup(self):
        pass

    def get_user_from_authorization(self, authorization):
        if not authorization:
            return

        user = models.User.create_or_get(self.session, authorization.username)

        if user.validate_password(authorization.password):
            return user

    def create_api_key_for_user(self, user):
        key = models.Key(user=user)
        self.session.add(key)
        self.session.commit()

        return key
