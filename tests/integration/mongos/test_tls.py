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
    MONGOS_CLUSTER_COMPONENTS,
    assert_mongos_tls_disabled,
    assert_mongos_tls_enabled,
    build_cluster,
    deploy_cluster_components,
    get_k8s_public_ip,
    get_sans_ips,
    rotate_and_verify_certs,
    toggle_tls_mongos,
)
from tests.integration.helpers.tls import (
    DIFFERENT_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_APP_NAME,
    integrate_apps_with_tls,
)
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
    await build_cluster(ops_test, substrate, integrate_with_mongos=True, integrate_with_client=True)

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
    await integrate_apps_with_tls(ops_test, applications=[MONGOS_APP_NAME])

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        MONGOS_APP_NAME,
        status="Invalid peer-certificates relation.",
        timeout=TIMEOUT,
        subordinate=(substrate == "lxd"),
    )

    await check_status_detail(
        ops_test,
        MONGOS_APP_NAME,
        status="blocked",
        message="Peer TLS must be disabled in mongos, since it is disabled on the config-server in the cluster relation.",
    )

    await integrate_apps_with_tls(ops_test, applications=MONGOS_CLUSTER_COMPONENTS)
    await ops_test.model.wait_for_idle(
        apps=MONGOS_CLUSTER_COMPONENTS + [MONGOS_APP_NAME],
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
        status="active",
    )

    await assert_mongos_tls_enabled(ops_test, substrate)


@pytest.mark.skip_if_substrate("lxd")
@pytest.mark.abort_on_fail
async def test_mongos_tls_nodeport(ops_test: OpsTest, substrate: Substrate):
    """Tests that TLS is stable on nodeport enablement/removal."""
    # test that charm can enable nodeport without breaking mongos or accidentally disabling TLS
    await ops_test.model.applications[MONGOS_APP_NAME].set_config({"expose-external": "nodeport"})

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME],
        idle_period=60,
        status="active",
        timeout=TIMEOUT,
    )
    for internal in [True, False]:
        await assert_mongos_tls_enabled(ops_test, substrate, internal=internal)

    # check for expected IP addresses in the pem file
    for unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        assert get_k8s_public_ip() in await get_sans_ips(ops_test, unit, internal=True)
        assert get_k8s_public_ip() in await get_sans_ips(ops_test, unit, internal=False)

    # test that charm can disable nodeport without breaking mongos or accidentally disabling TLS
    await ops_test.model.applications[MONGOS_APP_NAME].set_config({"expose-external": "none"})
    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME],
        idle_period=60,
        status="active",
        timeout=TIMEOUT,
    )

    await assert_mongos_tls_enabled(ops_test, substrate, internal=True)

    # check for no public k8s IP address in the pem file
    for unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        assert get_k8s_public_ip() not in await get_sans_ips(ops_test, unit, internal=True)
        assert get_k8s_public_ip() not in await get_sans_ips(ops_test, unit, internal=False)


@pytest.mark.abort_on_fail
async def test_mongos_rotate_certs(ops_test: OpsTest, substrate: Substrate) -> None:
    await rotate_and_verify_certs(ops_test, substrate, MONGOS_APP_NAME)


@pytest.mark.abort_on_fail
async def test_mongos_tls_disabled(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos charm can disable TLS."""
    await toggle_tls_mongos(ops_test, enable=False)
    await ops_test.model.wait_for_idle(
        apps=MONGOS_CLUSTER_COMPONENTS + [MONGOS_APP_NAME, TLS_CERTIFICATES_APP_NAME],
        idle_period=60,
        timeout=TIMEOUT,
        raise_on_blocked=False,
    )

    await assert_mongos_tls_disabled(ops_test, substrate)

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
async def test_tls_reenabled(ops_test: OpsTest, substrate: Substrate) -> None:
    """Test that mongos can enable TLS after being integrated to cluster ."""
    await toggle_tls_mongos(ops_test, enable=True)
    await assert_mongos_tls_enabled(ops_test, substrate)


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
        status="Peer CA mismatch.",
        timeout=TIMEOUT,
        subordinate=(substrate == "lxd"),
    )

    await check_status_detail(
        ops_test,
        MONGOS_APP_NAME,
        status="blocked",
        message="The mongos peer CA and Config-Server peer CA don't match.",
    )
