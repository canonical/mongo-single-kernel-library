#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from datetime import datetime

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    SHARD_ONE_APP_NAME,
    SHARD_TWO_APP_NAME,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import read_remote_file
from tests.integration.helpers.jubilant_rollingops import (
    ETCD_APP_NAME,
    deploy_etcd,
    integrate_shard_with_etcd,
)
from tests.integration.helpers.jubilant_sharding import (
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.jubilant_tls import integrate_apps_with_tls
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
) -> None:
    deploy_etcd(juju)

    deploy_cluster_components(
        juju,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
    )

    integrate_sharding_components(juju)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_integrate_shard_with_etcd(juju: jubilant.Juju) -> None:
    """Integrate shard components with etcd cluster.

    Establishes the etcd integration for all cluster components and verifies
    that all components reach active status.
    """
    integrate_shard_with_etcd(juju, *CLUSTER_COMPONENTS)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            ETCD_APP_NAME,
            idle_period=30,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_enable_tls_in_shard_using_rolling_ops(juju: jubilant.Juju, substrate: Substrate) -> None:
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
    integrate_apps_with_tls(juju, *CLUSTER_COMPONENTS, peer=True, client=False)
    tls_start_time = datetime.now()

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, *CLUSTER_COMPONENTS, idle_period=30, unit_count={}
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    log_file_path = "/var/lib/rollingops/etcd_rollingops_worker.log"
    lock_message = "Lock granted using lease"

    for app_name in CLUSTER_COMPONENTS:
        for unit_name in juju.status().get_units(app_name):
            stdout = read_remote_file(juju, substrate, unit_name, log_file_path)
            assert stdout.strip(), f"Log file {log_file_path} is empty on {unit_name}"
            logger.info(f"{unit_name}: {log_file_path} size: {len(stdout)} bytes")

            lock_entry = None
            for line in reversed(stdout.split("\n")):
                if lock_message in line:
                    lock_entry = line
                    break

            assert lock_entry, f"'{lock_message}' not found in log on {unit_name}"

            timestamp_str = lock_entry.split()[0] + " " + lock_entry.split()[1].split(",")[0]
            lock_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            assert (
                lock_time >= tls_start_time
            ), f"Lock time on {unit_name} ({lock_time}) is before TLS start ({tls_start_time})"

            logger.info(
                f"{unit_name}: Lock granted at {lock_time}, TLS started at {tls_start_time}"
            )
