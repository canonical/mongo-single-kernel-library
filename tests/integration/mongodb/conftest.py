# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
from collections.abc import Generator
from typing import Any

import jubilant
import pytest

from tests.integration.helpers.jubilant_ha import k8s_deploy_chaos_mesh, k8s_destroy_chaos_mesh
from tests.integration.helpers.types import Substrate


@pytest.fixture
def base_app_name(mongod_metadata) -> str:
    """Default application name for testing."""
    return mongod_metadata["name"]


@pytest.fixture(scope="module")
def jubilant_chaos_mesh(juju: jubilant.Juju, substrate: Substrate) -> Generator[None, Any, Any]:
    assert juju.model
    if substrate == Substrate.k8s:
        k8s_deploy_chaos_mesh(juju.model)
        yield
        k8s_destroy_chaos_mesh(juju.model)
    else:
        yield
