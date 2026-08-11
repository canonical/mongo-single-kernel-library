#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    MONGOS_APP_NAME,
    TIMEOUT,
    check_status_detail,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.mongos import (
    MONGOS_CLIENT_APPLICATION,
    MONGOS_CLUSTER_COMPONENTS,
    assert_mongos_tls_enabled,
    build_cluster,
    deploy_cluster_components,
)
from tests.integration.helpers.tls import (
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
    integrate_apps_with_tls,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        application_path,
    )
    if substrate == "lxd":
        await ops_test.model.applications[MONGOS_CLIENT_APPLICATION].set_config(
            {"external-connectivity": "false"}
        )
    await build_cluster(ops_test, substrate, integrate_with_mongos=True, integrate_with_client=True)

    config = {"ca-common-name": "Test CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
        config=config,
    )

    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
        raise_on_error=False,
    )


@pytest.mark.abort_on_fail
async def test_mongos_tls_enabled_on_cluster(ops_test: OpsTest, substrate: Substrate):
    """Tests that if we enable on cluster first, we end up in blocked state."""
    await integrate_apps_with_tls(ops_test, applications=MONGOS_CLUSTER_COMPONENTS)

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        MONGOS_APP_NAME,
        status="Missing peer-certificates relation.",
        timeout=TIMEOUT,
        subordinate=(substrate == "lxd"),
    )
    await check_status_detail(
        ops_test,
        MONGOS_APP_NAME,
        status="blocked",
        message="Peer TLS must be enabled in mongos, since it is enabled on the config-server in the cluster relation.",
    )


@pytest.mark.abort_on_fail
async def test_mongos_tls_enabled(ops_test: OpsTest, substrate: Substrate):
    """Tests that if we then add the TLS integration on mongos it resolves."""
    assert ops_test.model
    await integrate_apps_with_tls(ops_test, applications=[MONGOS_APP_NAME])
    await ops_test.model.wait_for_idle(
        apps=MONGOS_CLUSTER_COMPONENTS + [MONGOS_APP_NAME],
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
        status="active",
    )

    await assert_mongos_tls_enabled(ops_test, substrate)
