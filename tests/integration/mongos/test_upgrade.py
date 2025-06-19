#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers.common import MONGOS_APP_NAME, TIMEOUT
from ..helpers.mongos import build_cluster, deploy_cluster_components
from ..helpers.types import Substrate
from ..helpers.upgrade import refresh_charm


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
        channel="6/edge",
        mongos_units=2,
    )
    await build_cluster(ops_test, substrate, integrate_with_mongos=True)


@pytest.mark.abort_on_fail
async def test_upgrade(
    ops_test: OpsTest, substrate: Substrate, mongos_charm: str, mongos_resource: dict
):
    await refresh_charm(ops_test, substrate, MONGOS_APP_NAME, mongos_charm, mongos_resource)
    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME], status="active", timeout=TIMEOUT, idle_period=120
    )
