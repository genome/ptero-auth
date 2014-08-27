from .base import BaseUserInfoProvider
from ptero_auth import exceptions
import grp
import pexpect
import pwd


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
        return check_login(user.name, password)


def check_login(username, password):
    try:
        child = pexpect.spawn('/bin/su - %s'%(username))
        child.expect('Password:')
        child.sendline(password)
        result=child.expect(['su: Authentication failure',username])
        child.close()
    except Exception as err:
        child.close()
        print ("Error authenticating. Reason: "%(err))
        return False
    if result == 0:
        print ("Authentication failed for user %s."%(username))
        return False
    else:
        print ("Authentication succeeded for user %s."%(username))
        return True


def _get_group_structs_for(user):
    return [g for g in grp.getgrall() if user.name in g.gr_mem]
