# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from collections.abc import AsyncGenerator
from typing import Any

import pytest
from juju.model import Model
from kubernetes.config.config_exception import ConfigException
from pytest_operator.plugin import OpsTest

TIMEOUT = 15 * 60


@pytest.fixture(scope="module")
async def kubernetes_model(
    ops_test: OpsTest,
) -> AsyncGenerator[Model, Any]:
    try:
        k8s_cloud = await ops_test.add_k8s(skip_storage=False)
    except (ConfigException, TypeError):
        pytest.fail("No Kubernetes config found to add-k8s")
    # deploy the glauth-k8s charm
    kubernetes_model = await ops_test.track_model(
        "secondary", cloud_name=k8s_cloud, keep=ops_test.ModelKeep.NEVER
    )
    yield kubernetes_model

    await ops_test.forget_model(alias="secondary", timeout=TIMEOUT, allow_failure=True)
