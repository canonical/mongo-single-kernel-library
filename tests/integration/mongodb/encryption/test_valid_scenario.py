#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio

from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    CHARMED_OPERATOR_USERNAME,
    TIMEOUT,
    UNIT_IDS,
    check_app_status,
    deploy_charm,
    execute_on_mongod,
    get_address_of_unit,
    get_app_name,
    get_password,
    has_file,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.types import Substrate
from tests.integration.helpers.vault import VAULT_KV_RELATION, deploy_vault, vault_base_path


async def test_deploy_charms(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
    vault_charm_name: str,
):
    await asyncio.gather(
        deploy_vault(ops_test, substrate, vault_charm_name),
        deploy_charm(
            ops_test=ops_test,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=len(UNIT_IDS),
            config={"enable-encryption-at-rest": True},
        ),
    )
    await ops_test.model.wait_for_idle(apps=[base_app_name], status="blocked", timeout=TIMEOUT)


async def test_no_integration_goes_to_blocked(ops_test: OpsTest, substrate: Substrate):
    app_name = await get_app_name(ops_test)
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        app_name,
        status="Must be integrated with vault to enable encryption at rest.",
    )
    await check_app_status(
        ops_test,
        app_name,
        status="blocked",
        message="Must be integrated with vault to enable encryption at rest.",
    )


async def test_integration_goes_to_active(
    ops_test: OpsTest, substrate: Substrate, vault_charm_name: str
):
    app_name = await get_app_name(ops_test)
    assert ops_test.model
    await ops_test.model.integrate(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=TIMEOUT)

    password = await get_password(ops_test, username=CHARMED_OPERATOR_USERNAME, app_name=app_name)
    for unit in ops_test.model.applications[app_name].units:
        for filename in ("role_id", "role_secret_id", "vault-cert.pem", "vaultTokenFile"):
            assert await has_file(ops_test, substrate, unit, vault_base_path(substrate), filename)

        host = await get_address_of_unit(
            ops_test, substrate, int(unit.name.split("/")[1]), app_name
        )

        replica_set_uri = f"mongodb://{CHARMED_OPERATOR_USERNAME}:{password}@{host}/admin"
        command = "db.adminCommand({getCmdLineOpts: 1})"
        result = await execute_on_mongod(
            ops_test, app_name, substrate, uri=replica_set_uri, command=command
        )
        assert result.succeeded
        assert result.data.get("parsed", {}).get("security", {}).get("enableEncryption", False)


async def test_rotate_master_key(ops_test: OpsTest, substrate: Substrate, vault_charm_name: str):
    pass


async def remove_relation_goes_to_blocked(
    ops_test: OpsTest, substrate: Substrate, vault_charm_name: str
):
    app_name = await get_app_name(ops_test)
    assert ops_test.model
    await ops_test.model.applications[app_name].remove_relation(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        app_name,
        status="Must be integrated with vault to enable encryption at rest.",
    )
    await check_app_status(
        ops_test,
        app_name,
        status="blocked",
        message="Must be integrated with vault to enable encryption at rest.",
    )
