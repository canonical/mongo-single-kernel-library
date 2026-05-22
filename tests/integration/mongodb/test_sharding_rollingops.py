#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import DEPLOYMENT_TIMEOUT, TIMEOUT
from tests.integration.helpers.rollingops import (
    ETCD_APP_NAME,
    deploy_etcd,
    integrate_shard_with_etcd,
)
from tests.integration.helpers.sharding import (
    CLUSTER_COMPONENTS,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.tls import (
    PEER_TLS_RELATION_NAME,
    TLS_CERTIFICATES_APP_NAME,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: Path,
    substrate: Substrate,
    mongod_resource,
) -> None:
    await deploy_etcd(ops_test)

    await deploy_cluster_components(
        ops_test,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
    )
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
        raise_on_blocked=False,
    )

    await integrate_sharding_components(ops_test)
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_integrate_shard_with_etcd(ops_test: OpsTest) -> None:
    await integrate_shard_with_etcd(ops_test, CLUSTER_COMPONENTS)

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS + [ETCD_APP_NAME],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_enable_tls_in_shard_using_rolling_ops(ops_test: OpsTest) -> None:
    for app in CLUSTER_COMPONENTS:
        await ops_test.model.integrate(TLS_CERTIFICATES_APP_NAME, f"{app}:{PEER_TLS_RELATION_NAME}")

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS, idle_period=20, timeout=TIMEOUT, status="active"
    )

    log_file_path = "/var/lib/rollingops/etcd_rollingops_worker.log"

    for app_name in CLUSTER_COMPONENTS:
        app = ops_test.model.applications[app_name]
        for unit in app.units:
            ssh_command = ["ssh", unit.name, "sudo", "cat", log_file_path]
            return_code, stdout, stderr = await ops_test.juju(*ssh_command)

            assert return_code == 0, f"Failed to read log file on {unit.name}: {stderr}"
            assert stdout.strip(), f"Log file {log_file_path} is empty on {unit.name}"

            logger.info(f"{unit.name}: {log_file_path} size: {len(stdout)} bytes")
