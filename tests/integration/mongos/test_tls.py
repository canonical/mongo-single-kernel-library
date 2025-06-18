#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    MONGOS_APP_NAME,
    TIMEOUT,
    wait_for_mongodb_units_blocked,
)
from ..helpers.mongos import (
    build_cluster,
    check_mongos_tls_disabled,
    check_mongos_tls_enabled,
    deploy_cluster_components,
    integrate_cluster_with_tls,
    rotate_and_verify_certs,
    toggle_tls_mongos,
)
from ..helpers.tls import (
    DIFFERENT_CERTIFICATES_APP_NAME,
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

    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
        raise_on_error=False,
    )


@pytest.mark.abort_on_fail
async def test_mongos_tls_enabled(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos charm can enable TLS."""
    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}:{TLS_RELATION_NAME}",
        f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        MONGOS_APP_NAME,
        status="mongos has TLS enabled, but config-server does not.",
        timeout=TIMEOUT,
        subordinate=(substrate == "lxd"),
    )

    await integrate_cluster_with_tls(ops_test)

    await check_mongos_tls_enabled(ops_test, substrate)


@pytest.mark.abort_on_fail
async def test_mongos_rotate_certs(ops_test: OpsTest, substrate: Substrate) -> None:
    await rotate_and_verify_certs(ops_test, substrate, MONGOS_APP_NAME)


@pytest.mark.abort_on_fail
async def test_mongos_tls_disabled(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos charm can disable TLS."""
    await toggle_tls_mongos(ops_test, enable=False)
    await check_mongos_tls_disabled(ops_test, substrate)

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME],
        idle_period=60,
        timeout=TIMEOUT,
        raise_on_blocked=False,
    )

    for mongos_unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        assert (
            mongos_unit.workload_status_message == "mongos requires TLS to be enabled."
        ), "mongos fails to report TLS inconsistencies."


@pytest.mark.abort_on_fail
async def test_tls_reenabled(ops_test: OpsTest, substrate: Substrate) -> None:
    """Test that mongos can enable TLS after being integrated to cluster ."""
    await toggle_tls_mongos(ops_test, enable=True)
    await check_mongos_tls_enabled(ops_test, substrate)


@pytest.mark.abort_on_fail
async def test_mongos_tls_ca_mismatch(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos charm can disable TLS."""
    await toggle_tls_mongos(ops_test, enable=False)

    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        application_name=DIFFERENT_CERTIFICATES_APP_NAME,
        channel="latest/stable",
        base="ubuntu@22.04",
    )

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME],
        idle_period=60,
        timeout=TIMEOUT,
        raise_on_blocked=False,
    )

    await ops_test.model.wait_for_idle(
        apps=[DIFFERENT_CERTIFICATES_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        status="active",
        timeout=TIMEOUT,
    )

    await toggle_tls_mongos(ops_test, enable=True, certs_app_name=DIFFERENT_CERTIFICATES_APP_NAME)

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        MONGOS_APP_NAME,
        status="mongos CA and Config-Server CA don't match.",
        timeout=TIMEOUT,
        subordinate=(substrate == "lxd"),
    )
