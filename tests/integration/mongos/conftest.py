# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import pytest


@pytest.fixture
def base_app_name(mongos_metadata) -> str:
    """Default application name for testing."""
    return mongos_metadata["name"]
