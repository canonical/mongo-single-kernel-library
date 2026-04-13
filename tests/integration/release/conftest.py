# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from collections.abc import AsyncGenerator
from logging import getLogger
from typing import Any

import pytest
from juju.model import Model
from kubernetes.config.config_exception import ConfigException
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import MONGOS_APP_NAME, get_app_name
from tests.integration.helpers.ldap import LDAP_CERT_OFFER, LDAP_OFFER, teardown_offers
from tests.integration.helpers.sharding import (
    CONFIG_SERVER_APP_NAME,
)

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


@pytest.fixture(scope="module")
async def kubernetes_model(ops_test: OpsTest) -> AsyncGenerator[Model]:
    try:
        k8s_cloud = await ops_test.add_k8s(skip_storage=False)
        logger.warning(f"created cloud {k8s_cloud}")
    except (ConfigException, TypeError):
        pytest.fail("No Kubernetes config found to add-k8s")
    # deploy the glauth-k8s charm
    kubernetes_model = await ops_test.track_model(
        "secondary", cloud_name=k8s_cloud, keep=ops_test.ModelKeep.NEVER
    )
    logger.warning(f"Created model {kubernetes_model.name}")

    yield kubernetes_model

    for app_name in (
        await get_app_name(ops_test),
        await get_app_name(ops_test, CONFIG_SERVER_APP_NAME),
        await get_app_name(ops_test, MONGOS_APP_NAME),
    ):
        if app_name is None:
            continue
        try:
            await ops_test.model.applications[app_name].remove_relation(
                f"{LDAP_OFFER}:ldap", f"{app_name}:ldap"
            )
            await ops_test.model.applications[app_name].remove_relation(
                f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer"
            )
        except Exception:
            pass

    # Remove the offers and tear down deployment
    try:
        await teardown_offers(ops_test, kubernetes_model)
    except Exception:
        pass
    await ops_test.forget_model(alias="secondary", timeout=TIMEOUT, allow_failure=True)
