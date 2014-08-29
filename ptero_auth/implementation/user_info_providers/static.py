from .base import BaseUserInfoProvider
from ptero_auth.utils import safe_compare


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
        correct_password = self.data.get('passwords', {}).get(user.name)
        return safe_compare(correct_password, password)
