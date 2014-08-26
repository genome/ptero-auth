import os


def get_test_data_path(relative_path):
    return os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'data', relative_path))
