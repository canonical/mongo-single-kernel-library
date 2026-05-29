#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from datetime import datetime
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import DEPLOYMENT_TIMEOUT, TIMEOUT, read_remote_file
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
from tests.integration.helpers.tls import integrate_apps_with_tls
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
    """Integrate shard components with etcd cluster.

    Establishes the etcd integration for all cluster components and verifies
    that all components reach active status.
    """
    await integrate_shard_with_etcd(ops_test, CLUSTER_COMPONENTS)

    await ops_test.model.wait_for_idle(
        status="active",
        apps=CLUSTER_COMPONENTS + [ETCD_APP_NAME],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_enable_tls_in_shard_using_rolling_ops(
    ops_test: OpsTest, substrate: Substrate
) -> None:
    """Enable TLS for shard components and verify rolling ops etcd lock acquisition.

    Integrates TLS certificates for all cluster components and verifies that
    the rolling ops worker successfully acquires a distributed lock via etcd lease.
    Parses the worker log file to confirm "Lock granted using lease" entry exists
    with a timestamp after TLS enablement began.

    Log entry format example:
        2026-05-21 13:36:24,692 [INFO] [77172]
        [unit=config-server4/0 cluster=7sSW9jUx
         owner=53a5e2f6-7c0e-4017-8a36-c61093fa17ab-config-server4-0]
        __main__: Lock granted using lease 278b9e4abfac811b.
    """
    await integrate_apps_with_tls(ops_test, CLUSTER_COMPONENTS, peer=True, client=False)
    tls_start_time = datetime.now()

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS, idle_period=20, timeout=TIMEOUT, status="active"
    )

    log_file_path = "/var/lib/rollingops/etcd_rollingops_worker.log"
    lock_message = "Lock granted using lease"

    for app_name in CLUSTER_COMPONENTS:
        app = ops_test.model.applications[app_name]
        for unit in app.units:
            stdout = await read_remote_file(ops_test, substrate, unit.name, log_file_path)
            assert stdout.strip(), f"Log file {log_file_path} is empty on {unit.name}"
            logger.info(f"{unit.name}: {log_file_path} size: {len(stdout)} bytes")

            lock_entry = None
            for line in reversed(stdout.split("\n")):
                if lock_message in line:
                    lock_entry = line
                    break

            assert lock_entry, f"'{lock_message}' not found in log on {unit.name}"

            timestamp_str = lock_entry.split()[0] + " " + lock_entry.split()[1].split(",")[0]
            lock_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            assert (
                lock_time >= tls_start_time
            ), f"Lock time on {unit.name} ({lock_time}) is before TLS start ({tls_start_time})"

            logger.info(
                f"{unit.name}: Lock granted at {lock_time}, TLS started at {tls_start_time}"
            )
