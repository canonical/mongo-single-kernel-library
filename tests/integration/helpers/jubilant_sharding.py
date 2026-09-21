#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant
from pymongo import MongoClient

from single_kernel_mongo.config.statuses import ConfigServerStatuses, ShardStatuses
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    DEPLOYMENT_TIMEOUT,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    SHARD_TWO_APP_NAME,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    find_leader,
    get_ip_from_unit,
    get_ips_for_app,
    get_password,
    mongos_uri,
    verify_cluster_ip_source_allowlist,
)
from tests.integration.helpers.status_helpers import are_agents_idle, does_status_match
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


def deploy_cluster_components(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    num_units_cluster_config: dict[str, int] | None = None,
    config_server_name: str = CONFIG_SERVER_APP_NAME,
    shard_one_name: str = SHARD_ONE_APP_NAME,
    shard_two_name: str = SHARD_TWO_APP_NAME,
    channel: str | None = None,
    base: str | None = None,
    extra_config_config_server: dict[str, str] | None = None,
) -> None:
    if not extra_config_config_server:
        extra_config_config_server = {}
    if not num_units_cluster_config:
        num_units_cluster_config = {
            config_server_name: 2,
            shard_one_name: 3,
            shard_two_name: 1,
        }

    if channel is None:
        my_charm = mongodb_charm
    else:
        my_charm = "mongodb" if substrate == "lxd" else "mongodb-k8s"

    deploy_charm(
        juju,
        my_charm,
        substrate,
        app_name=config_server_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[config_server_name],
        channel=channel,
        config={"role": "config-server"} | extra_config_config_server,
        base=base,
    )
    deploy_charm(
        juju,
        my_charm,
        substrate,
        app_name=shard_one_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_one_name],
        channel=channel,
        config={"role": "shard"},
        base=base,
    )
    deploy_charm(
        juju,
        my_charm,
        substrate,
        app_name=shard_two_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_two_name],
        channel=channel,
        config={"role": "shard"},
        base=base,
    )

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                CONFIG_SERVER_APP_NAME,
                SHARD_ONE_APP_NAME,
                SHARD_TWO_APP_NAME,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    CONFIG_SERVER_APP_NAME: [ConfigServerStatuses.MISSING_CONF_SERVER_REL.value],
                    SHARD_ONE_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
                    SHARD_TWO_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
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


def integrate_sharding_components(
    juju: jubilant.Juju,
    config_server_name: str = CONFIG_SERVER_APP_NAME,
    shard_one_name: str = SHARD_ONE_APP_NAME,
    shard_two_name: str = SHARD_TWO_APP_NAME,
) -> None:
    """Integrates the cluster components with each other."""
    juju.integrate(
        f"{shard_one_name}:{SHARD_REL_NAME}",
        f"{config_server_name}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.integrate(
        f"{shard_two_name}:{SHARD_REL_NAME}",
        f"{config_server_name}:{CONFIG_SERVER_REL_NAME}",
    )


def get_cluster_shards(mongos_client: MongoClient) -> set[str]:
    """Returns a set of the shard members."""
    shard_list = mongos_client.admin.command("listShards")
    curr_members = [member["host"].split("/")[0] for member in shard_list["shards"]]
    return set(curr_members)


def has_correct_shards(mongos_client: MongoClient, expected_shards: list[str]) -> bool:
    """Returns true if the cluster config has the expected shards."""
    shard_names = get_cluster_shards(mongos_client)
    logger.info(f"Expecting {expected_shards}, got {shard_names}")
    return shard_names == set(expected_shards)


def verify_sharding_cluster_ip_source_allowlists(
    juju: jubilant.Juju,
    substrate: Substrate,
    config_server_app: str,
    shard_apps: set[str],
    related_shard_apps: set[str],
) -> None:
    """Verify cluster allowlists for the config server and every deployed shard.

    For k8s, the config server and shards only verify that its peers are in the allowlist.
    For VM, the config server and shards verify that all other cluster components are in
    the allowlist.
    """
    if substrate == "microk8s":
        for app_name in shard_apps | {config_server_app}:
            verify_cluster_ip_source_allowlist(juju, substrate, app_name)
        return

    config_server_addresses: set[str] = get_ips_for_app(juju, substrate, config_server_app)
    related_shard_addresses: set[str] = set()
    unrelated_shard_addresses: set[str] = set()
    for shard_app in shard_apps:
        addresses = get_ips_for_app(juju, substrate, shard_app)
        if shard_app in related_shard_apps:
            related_shard_addresses.update(addresses)
        else:
            unrelated_shard_addresses.update(addresses)

    verify_cluster_ip_source_allowlist(
        juju,
        substrate,
        config_server_app,
        additional_addresses=related_shard_addresses,
        excluded_addresses=unrelated_shard_addresses,
    )

    for shard_app in shard_apps:
        is_related = shard_app in related_shard_apps
        verify_cluster_ip_source_allowlist(
            juju,
            substrate,
            shard_app,
            additional_addresses=config_server_addresses if is_related else None,
            excluded_addresses=None if is_related else config_server_addresses,
        )


def build_mongos_client(juju: jubilant.Juju, substrate: Substrate, app_name: str) -> MongoClient:
    """Builds a mongos client."""
    _, leader_status = find_leader(juju, app_name=app_name)
    host = get_ip_from_unit(substrate=substrate, unit_info=leader_status)

    password = get_password(juju=juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)

    _mongos_uri = mongos_uri(CHARMED_OPERATOR_USERNAME, password, ip_addresses=[host])
    return MongoClient(_mongos_uri, directConnection=True)


def write_data_to_mongodb(client: MongoClient, db_name: str, coll_name: str, content: dict) -> None:
    """Writes data to the provided collection and database."""
    db = client[db_name]
    horses_collection = db[coll_name]
    horses_collection.insert_one(content)


def verify_data_mongodb(
    client: MongoClient, db_name: str, coll_name: str, key: str, value: str, shard: str
) -> bool:
    """Checks a key/value pair for a provided collection and database."""
    databases = client["config"]["databases"].find({"_id": db_name})
    assert databases[0]["primary"] == shard

    db = client[db_name]
    test_collection = db[coll_name]
    query = test_collection.find({}, {key: 1})
    return query[0][key] == value


def get_databases_for_shard(mongos_client: MongoClient, shard_name: str) -> list[str] | None:
    """Returns the databases hosted on the given shard."""
    config_db = mongos_client["config"]
    if "databases" not in config_db.list_collection_names():
        return None

    databases_collection = config_db["databases"]

    if databases_collection is None:
        return None

    return databases_collection.distinct("_id", {"primary": shard_name})


def shard_has_databases(
    mongos_client: MongoClient, shard_name: str, expected_databases_on_shard: list[str]
) -> bool:
    """Returns true if the provided shard is a primary for the provided databases."""
    databases_on_shard = get_databases_for_shard(mongos_client, shard_name=shard_name)
    if not databases_on_shard:
        return False
    return set(databases_on_shard) == set(expected_databases_on_shard)
