# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger
from typing import Any

import pytest

TIMEOUT = 15 * 60

logger = getLogger(__name__)


@pytest.fixture
def mongodb_base_app_name(mongod_metadata: dict[str, Any]) -> str:
    """Default application name for testing."""
    return mongod_metadata["name"]


@pytest.fixture
def mongos_base_app_name(mongos_metadata: dict[str, Any]) -> str:
    """Default application name for testing."""
    return mongos_metadata["name"]
