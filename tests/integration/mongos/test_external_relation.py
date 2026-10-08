#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

from single_kernel_mongo.config.statuses import MongosStatuses
from tests.integration.helpers.constants import (
    BASE,
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    DATA_INTEGRATOR_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    MONGOS_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    find_leader,
    get_connection_string,
)
from tests.integration.helpers.jubilant_mongos import (
    generate_mongos_uri,
    get_k8s_public_ip,
    is_mongos_running,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
) -> None:
    """Build and deploy a sharded cluster."""
    juju.deploy(DATA_INTEGRATOR_APP_NAME, channel="latest/stable", base=BASE)
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        config={"role": "config-server"},
    )
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=SHARD_ONE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )
    deploy_charm(
        juju,
        mongos_charm,
        substrate,
        app_name=MONGOS_APP_NAME,
        mongod_resource=mongos_resource,
        num_units=1,
    )
    juju.wait(
        lambda status: are_agents_idle(
            status,
            DATA_INTEGRATOR_APP_NAME,
            SHARD_ONE_APP_NAME,
            CONFIG_SERVER_APP_NAME,
            idle_period=20,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    if substrate == Substrate.k8s:
        juju.config(MONGOS_APP_NAME, {"expose-external": "nodeport"})
        juju.wait(
            lambda status: are_agents_idle(
                status,
                MONGOS_APP_NAME,
                idle_period=20,
            ),
            timeout=DEPLOYMENT_TIMEOUT,
        )


def test_mongos_starts_with_config_server(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify mongos is running and can be accessed externally via IP-address."""
    # mongos cannot start until it has a host application
    juju.config(
        DATA_INTEGRATOR_APP_NAME,
        {
            "database-name": "test-database",
        },
    )

    juju.integrate(DATA_INTEGRATOR_APP_NAME, MONGOS_APP_NAME)

    juju.wait(
        lambda status: (
            are_agents_idle(
                status, MONGOS_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, idle_period=20
            )
            and does_status_match(
                status, {MONGOS_APP_NAME: [MongosStatuses.MISSING_CONF_SERVER_REL.value]}
            )
        ),
        timeout=TIMEOUT,
    )
    # prepare sharded cluster
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    # connect sharded cluster to mongos
    juju.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    leader_name, _ = find_leader(juju, MONGOS_APP_NAME)
    uri = generate_mongos_uri(juju, substrate, MONGOS_APP_NAME, auth=False, external=True)
    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=leader_name,
        uri=uri,
    )
    assert mongos_running, "Mongos is not currently running."


def test_mongos_has_user(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify mongos has user and is able to connect externally via IP-address."""
    leader_name, _ = find_leader(juju, MONGOS_APP_NAME)
    uri = generate_mongos_uri(juju, substrate, DATA_INTEGRATOR_APP_NAME, auth=True, external=True)
    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=leader_name,
        uri=uri,
    )
    assert mongos_running, "Mongos is not currently running."


def test_mongos_can_scale(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify hosts are up to date after scaling."""
    # in order to scale mongos, we need to scale the host
    app_name = DATA_INTEGRATOR_APP_NAME if substrate == Substrate.lxd else MONGOS_APP_NAME
    n_units = len(juju.status().get_units(MONGOS_APP_NAME))
    ensure_app_number_units(juju, substrate, app_name=app_name, required_units=n_units + 1)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_APP_NAME, idle_period=20, unit_count=n_units + 1
        ),
        timeout=TIMEOUT,
    )
    rel_name = "mongos" if substrate == Substrate.lxd else "mongodb"
    uri_from_secret = get_connection_string(juju, DATA_INTEGRATOR_APP_NAME, rel_name)

    for mongos_unit_name, mongos_unit_status in juju.status().get_units(MONGOS_APP_NAME).items():
        if substrate == Substrate.lxd:
            mongos_ip = mongos_unit_status.public_address
        else:
            mongos_ip = get_k8s_public_ip()
        assert mongos_ip in uri_from_secret, f"host for {mongos_unit_name} is not present in URI"

        mongos_running = is_mongos_running(
            juju,
            substrate,
            app_name=DATA_INTEGRATOR_APP_NAME,
            unit_name=mongos_unit_name,
            uri=uri_from_secret,
        )
        assert mongos_running, f"Mongos is not currently running on unit {mongos_unit_name}."


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_ip_change_after_scale_down(juju: jubilant.Juju):
    """Destroy a unit and ensure that it's IP is removed from the URI."""
    first_mongos_host_name, first_mongos_host_status = next(
        iter(juju.status().get_units(MONGOS_APP_NAME).items())
    )

    # destroy the first unit so the hosts are different from when the application was deployed
    first_mongos_host_public_address = first_mongos_host_status.public_address
    juju.remove_unit(first_mongos_host_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_APP_NAME, DATA_INTEGRATOR_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    uri_from_secret = get_connection_string(juju, DATA_INTEGRATOR_APP_NAME, "mongos")
    assert (
        first_mongos_host_public_address not in uri_from_secret
    ), "old host is still present in URI"
