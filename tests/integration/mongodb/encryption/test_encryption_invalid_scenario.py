#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    TIMEOUT,
    UNIT_IDS,
    check_app_status,
    deploy_charm,
    find_unit,
    get_app_name,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.types import Substrate
from tests.integration.helpers.vault import VAULT_KV_RELATION, deploy_vault


@pytest.mark.abort_on_fail
async def test_deploy_charms(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
    vault_charm_name: str,
):
    assert ops_test.model
    await asyncio.gather(
        deploy_vault(ops_test, substrate, vault_charm_name),
        deploy_charm(
            ops_test=ops_test,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=len(UNIT_IDS),
            config={"enable-encryption-at-rest": False},
        ),
    )
    await ops_test.model.wait_for_idle(apps=[base_app_name], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_integration_goes_to_blocked(
    ops_test: OpsTest, substrate: Substrate, vault_charm_name: str
):
    app_name = await get_app_name(ops_test)
    assert ops_test.model
    await ops_test.model.integrate(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        app_name,
        status="The vault-kv interface cannot be used with encryption at rest disabled.",
    )
    await check_app_status(
        ops_test,
        app_name,
        status="blocked",
        message="The vault-kv interface cannot be used with encryption at rest disabled.",
    )


@pytest.mark.abort_on_fail
async def test_remove_relation_goes_to_normal(ops_test: OpsTest, vault_charm_name: str):
    app_name = await get_app_name(ops_test)
    assert ops_test.model
    await ops_test.model.applications[app_name].remove_relation(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_rotation_fails_if_not_okay(ops_test: OpsTest, substrate: Substrate):
    app_name = await get_app_name(ops_test)
    assert ops_test.model
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    action = await leader_unit.run_action("rotate-encryption-master-key")
    result = await action.wait()

    assert result.status == "failed"
    assert result.results["message"] == "Encryption at rest not enabled on this application."
