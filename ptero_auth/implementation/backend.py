from .oidc.factory import create_server
from . import models
import sqlalchemy.exc


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

    def register_client(self, user, client_data):
        scope_dict = self._create_or_get_scopes(
                self._get_used_client_scopes(client_data))

        allowed_scopes = set(client_data['allowed_scopes'])
        default_scopes = set(client_data.get('default_scopes', []))
        audience_for = set(client_data.get('audience_for', []))

        assert default_scopes.issubset(allowed_scopes)
        assert audience_for.issubset(allowed_scopes)

        client = models.Client(
                client_name=client_data['name'],
                client_type=client_data['type'],
                created_by=user,
                redirect_uri_regex=client_data['redirect_uri_regex'],
                allowed_scopes=[scope_dict[sv] for sv in allowed_scopes],
                default_scopes=[scope_dict[sv] for sv in default_scopes],
                audience_for=[scope_dict[sv] for sv in audience_for],
        )

        self.session.add(client)
        self.session.commit()

        return client.as_dict

    def _create_or_get_scopes(self, scope_values):
        result = {}
        for scope_value in scope_values:
            scope = models.Scope(value=scope_value)
            try:
                self.session.add(scope)
                self.session.commit()

            except sqlalchemy.exc.IntegrityError:
                self.session.rollback()
                scope = self.session.query(models.Scope
                        ).filter_by(value=scope_value).one()

            result[scope_value] = scope

        return result

    def _get_used_client_scopes(self, client_data):
        result = set()
        result.update(client_data.get('allowed_scopes', []))
        result.update(client_data.get('default_scopes', []))
        result.update(client_data.get('audience_for', []))
        return result

    def get_client(self, client_id):
        client = self.session.query(models.Client
                ).filter_by(client_id=client_id).first()

        if client:
            return client.as_dict
