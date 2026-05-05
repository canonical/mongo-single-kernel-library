#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
)
from tests.integration.helpers.rollingops import (
    deploy_etcd,
    integrate_shard_with_etcd,
)
from tests.integration.helpers.sharding import (
    CLUSTER_COMPONENTS,
    deploy_cluster_components,
    integrate_sharding_components,
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

    await integrate_shard_with_etcd(ops_test, CLUSTER_COMPONENTS)

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
