import abc


class BaseUserInfoProvider(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_user_data(self, user, field_names):  # pragma: no cover
        return NotImplemented

    @abc.abstractmethod
    def validate_password(self, user, password):  # pragma: no cover
        return NotImplemented
