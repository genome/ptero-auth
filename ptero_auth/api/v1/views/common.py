def require_authorization():
    return '', 401, {'WWW-Authenticate': 'Basic'}
