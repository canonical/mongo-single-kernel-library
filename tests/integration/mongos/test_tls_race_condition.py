#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import MONGOS_APP_NAME, TIMEOUT
from tests.integration.helpers.mongos import (
    MONGOS_CLUSTER_COMPONENTS,
    assert_mongos_tls_enabled,
    build_cluster,
    deploy_cluster_components,
)
from tests.integration.helpers.sharding import CLUSTER_REL_NAME, CONFIG_SERVER_APP_NAME
from tests.integration.helpers.tls import TLS_CERTIFICATES_APP_NAME, integrate_apps_with_tls
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict,
    mongos_resource: dict,
    mongos_client_application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        mongos_client_application_path,
    )
    await build_cluster(ops_test, substrate, integrate_with_mongos=False)
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel="latest/stable", base="ubuntu@22.04"
    )


@pytest.mark.abort_on_fail
async def test_mongos_tls_enabled(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests race condition: mongos charm can integrate with TLS and then the config-server."""
    await integrate_apps_with_tls(ops_test, applications=MONGOS_CLUSTER_COMPONENTS)
    await ops_test.model.wait_for_idle(
        apps=MONGOS_CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
        status="active",
    )
    await integrate_apps_with_tls(ops_test, applications=[MONGOS_APP_NAME])

    # integrate mongos with config-server
    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME],
        idle_period=20,
        status="active",
        timeout=TIMEOUT,
    )

    await assert_mongos_tls_enabled(ops_test, substrate)
