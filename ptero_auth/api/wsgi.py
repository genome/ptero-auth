from ptero_auth.api.application import create_app
import argparse
import logging
import os


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--log-level', default='INFO',
            help='Logging level')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    from ptero_auth.settings import get_from_env
    app = create_app(get_from_env())
    app.run(port=settings.port(), host='0.0.0.0')
