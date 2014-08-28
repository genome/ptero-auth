from .base import BaseUserInfoProvider


class StaticUserInfoProvider(BaseUserInfoProvider):
    def __init__(self, data):
        super(StaticUserInfoProvider, self).__init__()
        self.data = data

    def get_user_data(self, user, field_names):
        result = {}

        for field_name in field_names:
            result[field_name] = self.data['user_fields'][user.name][field_name]

        return result

    def validate_password(self, user, password):
        return self.data.get('passwords', {}).get(user.name) == password
