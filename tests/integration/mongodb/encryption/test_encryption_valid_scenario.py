#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    CHARMED_OPERATOR_USERNAME,
    TIMEOUT,
    UNIT_IDS,
    check_app_status,
    deploy_charm,
    execute_on_mongod,
    find_unit,
    get_address_of_unit,
    get_app_name,
    get_password,
    has_file,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.ha import verify_writes
from tests.integration.helpers.tls import scp_file_preserve_ctime
from tests.integration.helpers.types import Substrate
from tests.integration.helpers.vault import VAULT_KV_RELATION, deploy_vault, vault_base_path


@pytest.mark.abort_on_fail
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


@pytest.mark.abort_on_fail
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


@pytest.mark.abort_on_fail
async def test_integration_goes_to_active(
    ops_test: OpsTest, substrate: Substrate, vault_charm_name: str
) -> None:
    """If we integrate with vault, we go to active, everything is correctly set up."""
    app_name = await get_app_name(ops_test)
    assert ops_test.model

    # Integrate with vault.
    await ops_test.model.integrate(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )

    # We go to active.
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=TIMEOUT)

    password = await get_password(ops_test, username=CHARMED_OPERATOR_USERNAME, app_name=app_name)

    # For each unit, we can find the right files, and we can connect and check that encryption is
    # enabled.
    for unit in ops_test.model.applications[app_name].units:
        for filename in ("role_id", "role_secret_id", "vault_cert.pem", "vaultTokenFile"):
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


async def test_rotate_master_key(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db
) -> None:
    """This test verifies that the master key rotation happens successfully."""
    app_name = await get_app_name(ops_test)
    assert ops_test.model

    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)

    # We rotate the master key on one unit.
    action = await leader_unit.run_action("rotate-encryption-master-key")
    result = await action.wait()

    assert result.results["result"] == "success"

    # Checks that we find the correct string in the logs that proves that the master key
    # has been rotated.
    if substrate == "lxd":
        log_file = "/var/snap/charmed-mongodb/common/var/log/mongodb/mongodb.log"
    else:
        log_file = "/var/log/mongodb/mongodb.log"

    filename = Path(await scp_file_preserve_ctime(ops_test, substrate, leader_unit.name, log_file))

    data = filename.read_text()
    assert "Rotated master encryption key" in data

    filename.unlink()

    # verify that no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def remove_relation_goes_to_blocked(
    ops_test: OpsTest, substrate: Substrate, vault_charm_name: str, continuous_writes_to_db
) -> None:
    """Checks that removing the vault integration goes to blocked, but writes are continuing."""
    app_name = await get_app_name(ops_test)
    assert ops_test.model

    # Remove the relation.
    await ops_test.model.applications[app_name].remove_relation(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )

    # MongoDB unit all goes to blocked.
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        app_name,
        status="Must be integrated with vault to enable encryption at rest.",
    )
    # MongoDB app goes to blocked.
    await check_app_status(
        ops_test,
        app_name,
        status="blocked",
        message="Must be integrated with vault to enable encryption at rest.",
    )

    # verify that no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def reintegrate_goes_to_regular(
    ops_test: OpsTest, substrate: Substrate, vault_charm_name: str, continuous_writes_to_db
) -> None:
    """Checks that reintegrating goes back to normal state and we haven't missed writes."""
    app_name = await get_app_name(ops_test)
    assert ops_test.model

    await ops_test.model.integrate(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=TIMEOUT)

    # verify that no writes were skipped
    await verify_writes(ops_test, substrate, app_name)
