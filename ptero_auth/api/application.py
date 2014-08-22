from . import v1
from ..implementation.factory import Factory
import flask


__all__ = ['create_app']


def create_app(settings):
    factory = Factory(settings=settings)

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
