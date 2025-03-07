import pytest


@pytest.fixture
def base_app_name(mongod_metadata):
    return mongod_metadata["name"]
