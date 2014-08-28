from .oidc.factory import create_server
from . import models


class Backend(object):
    def __init__(self, session, signature_key, user_info_provider, admin_role):
        self.session = session
        self.oidc_server = create_server(session, signature_key)
        self.user_info_provider = user_info_provider
        self.admin_role = admin_role

    def cleanup(self):
        pass

    def get_user_from_authorization(self, authorization):
        if not authorization:
            return

        user = models.User.create_or_get(self.session, authorization.username)

        if self.user_info_provider.validate_password(user,
                authorization.password):
            return user

    def create_api_key_for_user(self, user):
        key = models.Key(user=user)
        self.session.add(key)
        self.session.commit()

        return key

    def is_user_admin(self, user):
        user_info = self.user_info_provider.get_user_data(user, ['roles'])

        return self.admin_role in user_info['roles']
