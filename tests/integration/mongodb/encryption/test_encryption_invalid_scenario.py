#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.


import jubilant
import pytest

from single_kernel_mongo.config.statuses import VaultStatuses
from tests.integration.helpers.constants import (
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    find_leader,
)
from tests.integration.helpers.jubilant_vault import VAULT_KV_RELATION, deploy_vault
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
    """Deploys MongoDB with encryption at rest disabled."""
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(
            juju, substrate=substrate, app_name=app_name, required_units=len(UNIT_IDS)
        )
        juju.config(
            app_name,
            {"enable-encryption-at-rest": False},
        )
    else:
        deploy_charm(
            juju=juju,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=len(UNIT_IDS),
        )

    deploy_vault(juju, substrate, vault_charm_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            base_app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_integration_goes_to_blocked(
    juju: jubilant.Juju, substrate: Substrate, vault_charm_name: str
):
    """Tests that integration with vault goes to blocked.

    This tests that if we integrate with Vault, while encryption at rest is disabled,
    the charm goes into blocked state with the correct critical status.
    """
    app_name = existing_app(juju)
    assert app_name

    # We integrate this vault, this should lead the charm to be blocked on unit and app level.
    juju.integrate(f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}")
    # Checks that the app and units are all in blocked status.
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
                    app_name: [VaultStatuses.VAULT_INTEGRATED.value],
                },
                expected_app_statuses={
                    app_name: [VaultStatuses.VAULT_INTEGRATED.value],
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_remove_relation_goes_to_normal(juju: jubilant.Juju, vault_charm_name: str):
    """Tests that removing the vault relation goes back to normal operation."""
    app_name = existing_app(juju)
    assert app_name

    # Removing the relation should lead to active status
    juju.remove_relation(
        f"{app_name}:{VAULT_KV_RELATION}", f"{vault_charm_name}:{VAULT_KV_RELATION}"
    )

    # We are in active status
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


@pytest.mark.abort_on_fail
def test_rotation_fails_if_not_okay(juju: jubilant.Juju):
    """This tests that we can't rotate the master key if encryption at rest is disabled."""
    app_name = existing_app(juju)
    assert app_name
    leader_unit, _ = find_leader(juju, app_name)

    # Trying to rotate the key fails with an error if encryption at rest is disabled.
    action = juju.run(leader_unit, "rotate-encryption-master-key")

    assert action.status == "failed"
    assert action.results["message"] == "Encryption at rest not enabled on this application."
