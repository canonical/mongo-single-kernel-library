#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import ssl

import httpx
import jubilant
import pytest

from single_kernel_mongo.config.statuses import VaultStatuses
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import verify_writes
from tests.integration.helpers.jubilant_common import (
    delete_file_on_remote,
    deploy_charm,
    execute_on_mongod,
    existing_app,
    find_leader,
    get_ip_from_unit,
    get_password,
    read_remote_file,
    unit_has_file,
    unit_uri,
)
from tests.integration.helpers.jubilant_vault import (
    VAULT_KV_RELATION,
    deploy_vault,
    vault_base_path,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
def test_deploy_charms(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
    vault_charm_name: str,
):
    deploy_vault(juju, substrate, vault_charm_name)
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
        config={"enable-encryption-at-rest": True},
    )
    juju.wait(lambda status: jubilant.all_blocked(status, base_app_name), timeout=TIMEOUT)


@pytest.mark.abort_on_fail
def test_no_integration_goes_to_blocked(juju: jubilant.Juju, substrate: Substrate):
    app_name = existing_app(juju)
    assert app_name

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [VaultStatuses.VAULT_NOT_INTEGRATED.value],
                },
                expected_app_statuses={
                    app_name: [VaultStatuses.VAULT_NOT_INTEGRATED.value],
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_integration_goes_to_active(
    juju: jubilant.Juju, substrate: Substrate, vault_charm_name: str
) -> None:
    """If we integrate with vault, we go to active, everything is correctly set up."""
    app_name = existing_app(juju)
    assert app_name

    # Integrate with vault.
    juju.integrate(f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}")

    # We go to active.
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    password = get_password(juju, username=CHARMED_OPERATOR_USERNAME, app_name=app_name)

    # For each unit, we can find the right files, and we can connect and check that encryption is
    # enabled.
    for unit_name, unit_status in juju.status().get_units(app_name).items():
        for filename in ("role_id", "role_secret_id", "vault_cert.pem", "vaultTokenFile"):
            assert unit_has_file(juju, substrate, unit_name, vault_base_path(substrate), filename)

        host = get_ip_from_unit(substrate, unit_status)

        uri = unit_uri(username=CHARMED_OPERATOR_USERNAME, password=password, ip_address=host)
        command = "db.serverStatus()"
        result = execute_on_mongod(juju, substrate, app_name, uri=uri, command=command)
        assert result.succeeded
        assert result.data.get("encryptionAtRest", {}).get("encryptionEnabled", False)


def test_vault_agent_metrics(juju: jubilant.Juju, substrate: Substrate):
    app_name = existing_app(juju)
    assert app_name
    if substrate == "lxd":
        ca_file = "/var/snap/charmed-mongodb/current/etc/vault/ca.pem"
    else:
        ca_file = "/etc/vault/ca.pem"

    for unit_name, unit_status in juju.status().get_units(app_name).items():
        unit_address = get_ip_from_unit(substrate, unit_status)
        vault_telemetry_url = f"https://{unit_address}:8200/agent/v1/metrics"
        ca_file = read_remote_file(
            juju,
            substrate,
            unit_name=unit_name,
            file_path=ca_file,
        )

        ctx = ssl.create_default_context(cadata=ca_file)
        mongo_resp = httpx.get(
            vault_telemetry_url, verify=ctx, headers={"Accept": "prometheus/telemetry"}
        )
        assert mongo_resp.status_code == 200
        assert "vault_agent_authenticated 1" in mongo_resp.text


def test_rotate_master_key(
    juju: jubilant.Juju, substrate: Substrate, continuous_writes_to_db
) -> None:
    """This test verifies that the master key rotation happens successfully."""
    app_name = existing_app(juju)
    assert app_name

    leader_unit, _ = find_leader(juju, app_name)

    # We rotate the master key on one unit.
    action = juju.run(unit=leader_unit, action="rotate-encryption-master-key")

    assert action.results["result"] == "success"

    # Checks that we find the correct string in the logs that proves that the master key
    # has been rotated.
    if substrate == "lxd":
        log_file = "/var/snap/charmed-mongodb/common/var/log/mongodb/mongodb.log"
    else:
        log_file = "/var/log/mongodb/mongodb.log"

    data = read_remote_file(juju, substrate, unit_name=leader_unit, file_path=log_file)
    assert "Rotated master encryption key" in data

    # verify that no writes were skipped
    verify_writes(juju, substrate, app_name)


@pytest.mark.abort_on_fail
def remove_relation_goes_to_blocked(
    juju: jubilant.Juju, substrate: Substrate, vault_charm_name: str, continuous_writes_to_db
) -> None:
    """Checks that removing the vault integration goes to blocked, but writes are continuing."""
    app_name = existing_app(juju)
    assert app_name

    # Remove the relation.
    juju.remove_relation(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )

    # MongoDB units and app all goes to blocked.
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [VaultStatuses.VAULT_NOT_INTEGRATED.value],
                },
                expected_app_statuses={
                    app_name: [VaultStatuses.VAULT_NOT_INTEGRATED.value],
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # verify that no writes were skipped
    verify_writes(juju, substrate, app_name)


@pytest.mark.abort_on_fail
def reintegrate_goes_to_regular(
    juju: jubilant.Juju, substrate: Substrate, vault_charm_name: str, continuous_writes_to_db
) -> None:
    """Checks that reintegrating goes back to normal state and we haven't missed writes."""
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}")
    # We go to active.
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # verify that no writes were skipped
    verify_writes(juju, substrate, app_name)


@pytest.mark.abort_on_fail
def test_remove_token_then_reintegrate(
    juju: jubilant.Juju, substrate: Substrate, vault_charm_name: str, continuous_writes_to_db
) -> None:
    """Checks that reintegrating goes back to normal state and we haven't missed writes."""
    app_name = existing_app(juju)
    assert app_name

    # Remove the relation.
    juju.remove_relation(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )
    # MongoDB units and app all goes to blocked.
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [VaultStatuses.VAULT_NOT_INTEGRATED.value],
                },
                expected_app_statuses={
                    app_name: [VaultStatuses.VAULT_NOT_INTEGRATED.value],
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    if substrate == "lxd":
        filepath = "/var/snap/charmed-mongodb/current/etc/vault/vaultTokenFile"
    else:
        filepath = "/etc/vault/vaultTokenFile"

    for unit_name in juju.status().get_units(app_name):
        delete_file_on_remote(juju, substrate, unit_name, filepath)

    juju.integrate(f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}")

    # We go to active.
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # verify that no writes were skipped
    verify_writes(juju, substrate, app_name)
