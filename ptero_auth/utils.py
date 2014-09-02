try:
    from hmac import compare_digest as _safe_compare
except ImportError:
    from oauthlib.common import safe_string_equals as _safe_compare


def safe_compare(a, b):
    return _safe_compare(unicode(a), unicode(b))
