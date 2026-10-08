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
    MONGOS_CLIENT_APPLICATION,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
)
from tests.integration.helpers.jubilant_mongos import (
    assert_all_unit_node_ports_are_unavailable,
    assert_all_unit_node_ports_available,
    assert_app_uri_matches_external_setting,
    get_node_port_info,
    is_external_mongos_client_reachable,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    mongos_client_application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    juju.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        base=BASE,
        config={"database-name": "test-database"},
    )
    juju.deploy(mongos_client_application_path, app=MONGOS_CLIENT_APPLICATION)
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
            MONGOS_CLIENT_APPLICATION,
            SHARD_ONE_APP_NAME,
            CONFIG_SERVER_APP_NAME,
            idle_period=20,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.integrate(DATA_INTEGRATOR_APP_NAME, MONGOS_APP_NAME)
    juju.wait(
        lambda status: (
            are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
            and does_status_match(
                status, {MONGOS_APP_NAME: [MongosStatuses.MISSING_CONF_SERVER_REL.value]}
            )
        ),
        timeout=TIMEOUT,
    )
    juju.integrate(MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME)
    juju.wait(
        lambda status: (
            are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
            and does_status_match(
                status, {MONGOS_APP_NAME: [MongosStatuses.MISSING_CONF_SERVER_REL.value]}
            )
        ),
        timeout=TIMEOUT,
    )

    juju.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            MONGOS_APP_NAME,
            DATA_INTEGRATOR_APP_NAME,
            MONGOS_CLIENT_APPLICATION,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_mongos_external_connections(juju: jubilant.Juju) -> None:
    """Tests that mongos is accessible externally."""
    configuration_parameters = {"expose-external": "nodeport"}

    # apply new configuration options
    juju.config(MONGOS_APP_NAME, configuration_parameters)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            MONGOS_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    # verify each unit has a node port available
    assert_all_unit_node_ports_available(juju)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_mongos_external_connections_scale(juju: jubilant.Juju) -> None:
    """Tests that new mongos units are accessible externally."""
    juju.add_unit(MONGOS_APP_NAME, num_units=1)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_APP_NAME, idle_period=20, unit_count=2
        ),
        timeout=TIMEOUT,
    )

    # verify each unit has a node port available
    assert_all_unit_node_ports_available(juju)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_mongos_bad_configuration(juju: jubilant.Juju) -> None:
    """Tests that an invalid expose-external setting raises the proper statuses.

    It also checks that rolling back to a correct value goes back to normal.
    """
    configuration_parameters = {"expose-external": "nonsensical-setting"}

    # apply invalid configuration options
    juju.config(MONGOS_APP_NAME, configuration_parameters)

    # verify that Charmed Mongos is blocked and reports incorrect credentials
    juju.wait(
        lambda status: (
            are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                {MONGOS_APP_NAME: [MongosStatuses.INVALID_EXPOSE_EXTERNAL.value]},
                expected_app_statuses={
                    MONGOS_APP_NAME: [MongosStatuses.INVALID_EXPOSE_EXTERNAL.value]
                },
            )
        ),
        timeout=TIMEOUT,
    )

    # verify new-configuration didn't break old configuration
    assert_all_unit_node_ports_available(juju)

    # reset config for other tests
    configuration_parameters = {"expose-external": "nodeport"}
    juju.config(MONGOS_APP_NAME, configuration_parameters)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGOS_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_all_clients_use_nodeport(juju: jubilant.Juju) -> None:
    """Test that all clients use nodeport."""
    # Set config to node port
    configuration_parameters = {"expose-external": "nodeport"}
    juju.config(MONGOS_APP_NAME, configuration_parameters)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGOS_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )
    assert_app_uri_matches_external_setting(
        juju, app_name=DATA_INTEGRATOR_APP_NAME, rel_name="mongodb", external=True
    )
    assert_app_uri_matches_external_setting(
        juju, app_name=MONGOS_CLIENT_APPLICATION, rel_name="mongodb", external=True
    )


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_mongos_disable_external_connections(juju: jubilant.Juju) -> None:
    """Tests that mongos can disable external connections."""
    # get exposed node port before toggling off exposure
    assert juju.model
    exposed_node_port = get_node_port_info(
        juju.model, node_port_name=f"{MONGOS_APP_NAME}-0-external"
    )

    configuration_parameters = {"expose-external": "none"}

    # apply new configuration options
    juju.config(MONGOS_APP_NAME, configuration_parameters)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, DATA_INTEGRATOR_APP_NAME, MONGOS_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    # verify each unit has a node port available
    assert_all_unit_node_ports_are_unavailable(juju)

    assert not is_external_mongos_client_reachable(juju, exposed_node_port)

    assert_app_uri_matches_external_setting(
        juju, app_name=DATA_INTEGRATOR_APP_NAME, rel_name="mongodb", external=False
    )
    assert_app_uri_matches_external_setting(
        juju, app_name=MONGOS_CLIENT_APPLICATION, rel_name="mongodb", external=False
    )
