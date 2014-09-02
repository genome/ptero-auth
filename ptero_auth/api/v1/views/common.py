from flask import request


def require_authorization(method='Basic realm="ptero"'):
    return '', 401, {
        'WWW-Authenticate': method,
        'Location': request.url,
    }
