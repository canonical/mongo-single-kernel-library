from collections.abc import AsyncGenerator
from logging import getLogger
from typing import Any

import pytest
from juju.model import Model
from pytest_operator.plugin import OpsTest

TIMEOUT = 15 * 60

logger = getLogger(__name__)


@pytest.fixture(scope="module")
async def kubernetes_model(ops_test: OpsTest, k8s_cloud: str) -> AsyncGenerator[Model, Any]:
    # deploy the glauth-k8s charm
    kubernetes_model = await ops_test.track_model(
        "secondary", cloud_name=k8s_cloud, keep=ops_test.ModelKeep.NEVER
    )
    logger.info(f"Created model {kubernetes_model.name}")
    yield kubernetes_model

    await ops_test.forget_model(alias="secondary", timeout=TIMEOUT, allow_failure=True)
