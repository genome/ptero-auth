# NOTE: This script will must be run as root.  It runs shell commands to create
# posix users and groups for testing purposes.

import argparse
import pwd
import subprocess
import yaml


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('user_data_filename')

    return parser.parse_args()


def main(filename):
    user_data = _get_user_data(filename)

    for group_name, gid in user_data['groups'].iteritems():
        _create_group(group_name, gid)

    for user_identifier, user_info in user_data['user_fields'].iteritems():
        posix = user_info['posix']
        password = user_data['passwords'][user_identifier]
        _create_user(password=password, **posix)

        _verify_user(user_info['username'])


def _get_user_data(filename):
    with open(filename) as f:
        return yaml.load(f)


def _create_group(name, gid):
    print 'Creating group:', name, gid
    subprocess.check_call(['groupadd', '-g', str(gid), name])


def _create_user(username, password, uid, gid, groups):
    print 'Creating user:', username, password, uid, gid, groups
    subprocess.check_call(
            ['useradd', '-u', str(uid), '-g', str(gid),
                '-G', ','.join(str(g) for g in groups), username])
    p = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE)
    stdout, stderr = p.communicate('%s:%s\n' % (username, password))


def _verify_user(username):
    pw_struct = pwd.getpwnam(username)
    if pw_struct:
        print 'Found user:', pw_struct

    else:
        print 'Failed to find user', username


if __name__ == '__main__':
    args = parse_args()
    main(args.user_data_filename)
