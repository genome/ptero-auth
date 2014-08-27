from .base import BaseUserInfoProvider
from ptero_auth import exceptions
import grp
import pwd
import subprocess


def _get_posix(user):
    pw_struct = pwd.getpwnam(user.name)
    group_structs = _get_group_structs_for(user)
    groups = [pw_struct.pw_gid] + [g.gr_gid for g in group_structs]

    return {
        'username': user.name,
        'uid': pw_struct.pw_uid,
        'gid': pw_struct.pw_gid,
        'groups': groups,
    }


def _get_roles(user):
    return [g.gr_name for g in _get_group_structs_for(user)]


_FIELD_CONSTRUCTORS = {
    'posix': _get_posix,
    'roles': _get_roles,
}


class PosixUserInfoProvider(BaseUserInfoProvider):
    def get_user_data(self, user, field_names):
        result = {}

        for field_name in field_names:
            if field_name not in _FIELD_CONSTRUCTORS:
                raise exceptions.InvalidFieldName(field_name)

            result['field_name'] = _FIELD_CONSTRUCTORS[field_name](user)

        return result

    def validate_password(self, user, password):
        p = subproces.Popen(['su', '-c', 'exit', username],
                stdin=subprocess.PIPE)
        p.communicate('%s\n' % password)
        return p.returncode == 0


def _get_group_structs_for(user):
    return [g for g in grp.getgrall() if user.name in g.gr_mem]
