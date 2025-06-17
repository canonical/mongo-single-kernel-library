#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers.common import MONGOS_APP_NAME, TIMEOUT
from ..helpers.mongos import (
    build_cluster,
    check_mongos_tls_enabled,
    deploy_cluster_components,
    integrate_cluster_with_tls,
)
from ..helpers.sharding import CLUSTER_REL_NAME, CONFIG_SERVER_APP_NAME
from ..helpers.tls import (
    TLS_CERTIFICATES_APP_NAME,
    TLS_RELATION_NAME,
)
from ..helpers.types import Substrate


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
    await build_cluster(ops_test, substrate, integrate_with_mongos=True)
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel="latest/stable", base="ubuntu@22.04"
    )


@pytest.mark.abort_on_fail
async def test_mongos_tls_enabled(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests race condition: mongos charm can integrate with TLS and then the config-server."""
    await integrate_cluster_with_tls(ops_test)
    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}:{TLS_RELATION_NAME}",
        f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
    )

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

    await check_mongos_tls_enabled(ops_test, substrate)
