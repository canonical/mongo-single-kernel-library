# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import pytest


@pytest.fixture
def base_app_name(mongod_metadata) -> str:
    """Default application name for testing."""
    return mongod_metadata["name"]
