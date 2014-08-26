import uuid


__all__ = ['generate_id']


def generate_id(suffix):
    return '%s:%s' % (uuid.uuid4().hex, suffix)
