# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import get_app_name
from tests.integration.helpers.ha import deploy_chaos_mesh, destroy_chaos_mesh, update_restart_delay
from tests.integration.helpers.types import Substrate

ORIGINAL_RESTART_DELAY = 5


@pytest.fixture
def base_app_name(mongod_metadata) -> str:
    """Default application name for testing."""
    return mongod_metadata["name"]


@pytest.fixture(scope="module")
def chaos_mesh(ops_test: OpsTest, substrate: Substrate) -> Generator[None, Any, Any]:
    if substrate == "microk8s":
        deploy_chaos_mesh(ops_test.model.info.name)
        yield
        destroy_chaos_mesh(ops_test.model.info.name)
    else:
        yield


@pytest.fixture()
async def reset_restart_delay(ops_test: OpsTest, substrate: Substrate, tmp_path: Path):
    """Resets service file delay on all units."""
    yield
    app_name = await get_app_name(ops_test)
    for unit in ops_test.model.applications[app_name].units:
        await update_restart_delay(ops_test, substrate, unit, ORIGINAL_RESTART_DELAY, tmp_path)
