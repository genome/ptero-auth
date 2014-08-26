from . import v1
from ..implementation.factory import Factory
import flask


__all__ = ['create_app']


def _get_user_info_provider(user_data):
    if user_data:
        from ..implementation.user_info_providers import static
        return static.StaticUserInfoProvider(user_data)

    else:
        from ..implementation.user_info_providers import posix
        return posix.PosixUserInfoProvider()


def create_app(settings, user_data=None):
    factory = Factory(settings=settings,
            user_info_provider=_get_user_info_provider(user_data))

    app = _create_app_from_blueprints()

    _attach_factory_to_app(factory, app)

    return app


def _create_app_from_blueprints():
    app = flask.Flask('PTero Auth Service')
    app.register_blueprint(v1.blueprint, url_prefix='/v1')

    return app


def _attach_factory_to_app(factory, app):
    @app.before_request
    def before_request():
        flask.g.backend = factory.create_backend()

    @app.teardown_request
    def teardown_request(exception):
        flask.g.backend.cleanup()
