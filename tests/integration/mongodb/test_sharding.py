#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from single_kernel_mongo.config.statuses import ConfigServerStatuses, ShardStatuses
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_PASSWORD,
    CHARMED_OPERATOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    get_password,
    remove_number_units,
    set_password,
)
from tests.integration.helpers.jubilant_sharding import (
    build_mongos_client,
    has_correct_shards,
    shard_has_databases,
    verify_data_mongodb,
    verify_sharding_cluster_ip_source_allowlists,
    write_data_to_mongodb,
)
from tests.integration.helpers.sharding import (
    CLUSTER_APPS,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    SHARD_THREE_APP_NAME,
    SHARD_TWO_APP_NAME,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate

# for now we have a large timeout due to the slow drainage of the `config.system.sessions`
# collection. More info here:
# https://stackoverflow.com/questions/77364840/mongodb-slow-chunk-migration-for-collection-config-system-sessions-with-remov
REMOVAL_TIMEOUT = 30 * 60

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
) -> None:
    """Build and deploy a sharded cluster."""
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=CONFIG_SERVER_APP_NAME,
        num_units=3,
        config={"role": "config-server"},
    )
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=SHARD_ONE_APP_NAME,
        num_units=3,
        config={"role": "shard"},
    )
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=SHARD_TWO_APP_NAME,
        num_units=3,
        config={"role": "shard"},
    )
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=SHARD_THREE_APP_NAME,
        num_units=3,
        config={"role": "shard"},
    )

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                CONFIG_SERVER_APP_NAME,
                SHARD_ONE_APP_NAME,
                SHARD_TWO_APP_NAME,
                SHARD_THREE_APP_NAME,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    CONFIG_SERVER_APP_NAME: [ConfigServerStatuses.MISSING_CONF_SERVER_REL.value],
                    SHARD_ONE_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
                    SHARD_TWO_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
                    SHARD_THREE_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
                },
                expected_app_statuses={
                    CONFIG_SERVER_APP_NAME: [ConfigServerStatuses.MISSING_CONF_SERVER_REL.value],
                },
            )
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_cluster_active(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests the integration of cluster components works without error."""
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.integrate(
        f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.integrate(
        f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            SHARD_THREE_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)

    # verify sharded cluster config
    assert has_correct_shards(
        mongos_client,
        expected_shards=[SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, SHARD_THREE_APP_NAME],
    ), "Config server did not process config properly"


@pytest.mark.abort_on_fail
def test_cluster_ip_source_allowlists(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify cluster allowlists contain the replica-set IPs expected for the substrate."""
    verify_sharding_cluster_ip_source_allowlists(
        juju,
        substrate,
        config_server_app=CONFIG_SERVER_APP_NAME,
        shard_apps={SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, SHARD_THREE_APP_NAME},
        related_shard_apps={SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, SHARD_THREE_APP_NAME},
    )


@pytest.mark.abort_on_fail
def test_set_operator_password(juju: jubilant.Juju):
    """Tests that the cluster can safely set the charmed_operator password."""
    for cluster_app_name in CLUSTER_APPS:
        operator_password = get_password(
            juju=juju, username=CHARMED_OPERATOR_USERNAME, app_name=cluster_app_name
        )
        assert (
            operator_password != CHARMED_OPERATOR_PASSWORD
        ), f"{cluster_app_name} is incorrectly already set to the new password."

    # rotate password and verify that no unit goes into error as a result of password rotation
    set_password(
        juju,
        username=CHARMED_OPERATOR_USERNAME,
        password=CHARMED_OPERATOR_PASSWORD,
        app_name=CONFIG_SERVER_APP_NAME,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            SHARD_THREE_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    for cluster_app_name in CLUSTER_APPS:
        operator_password = get_password(
            juju, username=CHARMED_OPERATOR_USERNAME, app_name=cluster_app_name
        )
        assert (
            operator_password == CHARMED_OPERATOR_PASSWORD
        ), f"{cluster_app_name} did not rotate to new password."


@pytest.mark.abort_on_fail
def test_sharding_write(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests writing data to mongos gets propagated to shards."""
    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)

    # write data to shard two
    write_data_to_mongodb(
        mongos_client,
        db_name="animals_database_1",
        coll_name="horses",
        content={"horse-breed": "unicorn", "real": True},
    )
    mongos_client.admin.command("movePrimary", "animals_database_1", to=SHARD_TWO_APP_NAME)

    # write data to shard three
    write_data_to_mongodb(
        mongos_client,
        db_name="animals_database_2",
        coll_name="horses",
        content={"horse-breed": "pegasus", "real": True},
    )
    mongos_client.admin.command("movePrimary", "animals_database_2", to=SHARD_THREE_APP_NAME)

    has_correct_data = verify_data_mongodb(
        mongos_client,
        db_name="animals_database_1",
        coll_name="horses",
        key="horse-breed",
        value="unicorn",
        shard=SHARD_TWO_APP_NAME,
    )
    assert has_correct_data, "data not written to shard-two"

    has_correct_data = verify_data_mongodb(
        mongos_client,
        db_name="animals_database_2",
        coll_name="horses",
        key="horse-breed",
        value="pegasus",
        shard=SHARD_THREE_APP_NAME,
    )
    assert has_correct_data, "data not written to shard-three"


@pytest.mark.abort_on_fail
def test_shard_removal(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Test shard removal.

    This test also verifies that:
    - Databases that are using this shard as a primary are moved.
    - The balancer is turned back on if turned off.
    - Config server supports removing multiple shards.
    """
    # turn off balancer.
    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)
    mongos_client.admin.command("balancerStop")

    balancer_state = mongos_client.admin.command("balancerStatus")
    assert balancer_state["mode"] == "off", "balancer was not successfully turned off"

    # remove two shards at the same time
    juju.remove_relation(
        app1=f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        app2=f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
    )
    juju.remove_relation(
        app1=f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        app2=f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            SHARD_THREE_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=REMOVAL_TIMEOUT,
        delay=5,
        successes=3,
    )

    # verify that config server turned back on the balancer
    balancer_state = mongos_client.admin.command("balancerStatus")
    assert balancer_state["mode"] != "off", "balancer not turned back on from config server"

    # verify sharded cluster config
    assert has_correct_shards(
        mongos_client, expected_shards=[SHARD_ONE_APP_NAME]
    ), "Config server did not process config properly"

    # verify no data lost
    assert shard_has_databases(
        mongos_client,
        shard_name=SHARD_ONE_APP_NAME,
        expected_databases_on_shard=["animals_database_1", "animals_database_2"],
    ), "Not all databases on final shard"

    if substrate == "lxd":
        verify_sharding_cluster_ip_source_allowlists(
            juju,
            substrate,
            config_server_app=CONFIG_SERVER_APP_NAME,
            shard_apps={SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, SHARD_THREE_APP_NAME},
            related_shard_apps={SHARD_ONE_APP_NAME},
        )


@pytest.mark.abort_on_fail
def test_removal_of_non_primary_shard(juju: jubilant.Juju, substrate: Substrate):
    """Tests safe removal of a shard that is not primary."""
    # add back a shard so we can safely remove a shard.

    logging.info("Adding %s to config server", SHARD_TWO_APP_NAME)
    juju.integrate(
        f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            SHARD_THREE_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    logging.info("Removing %s from config server", SHARD_TWO_APP_NAME)
    juju.remove_relation(
        f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=REMOVAL_TIMEOUT,
        delay=5,
        successes=3,
    )

    # build a mongos config-server client
    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)

    # verify sharded cluster config
    assert has_correct_shards(
        mongos_client, expected_shards=[SHARD_ONE_APP_NAME]
    ), "Config server did not process config properly"

    # verify no data lost
    assert shard_has_databases(
        mongos_client,
        shard_name=SHARD_ONE_APP_NAME,
        expected_databases_on_shard=["animals_database_1", "animals_database_2"],
    ), "Not all databases on final shard"


@pytest.mark.abort_on_fail
def test_unconventual_shard_removal(juju: jubilant.Juju, substrate: Substrate):
    """Tests that removing a shard application safely drains data.

    It is preferred that users remove-relations instead of removing shard applications. But we do
    support removing shard applications in a safe way.
    """
    # add back a shard so we can safely remove a shard.
    juju.integrate(
        f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_TWO_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    remove_number_units(juju, substrate, SHARD_TWO_APP_NAME, 1)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            SHARD_TWO_APP_NAME,
            idle_period=30,
            unit_count=2,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    juju.remove_application(SHARD_TWO_APP_NAME)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=REMOVAL_TIMEOUT,
        delay=5,
        successes=3,
    )

    # build a mongos config-server client
    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)

    # verify sharded cluster config
    assert has_correct_shards(
        mongos_client, expected_shards=[SHARD_ONE_APP_NAME]
    ), "Config server did not process config properly"

    # verify no data lost
    assert shard_has_databases(
        mongos_client,
        shard_name=SHARD_ONE_APP_NAME,
        expected_databases_on_shard=["animals_database_1", "animals_database_2"],
    ), "Not all databases on final shard"
