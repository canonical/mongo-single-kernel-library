from logging import getLogger

import jubilant
from pymongo import MongoClient

from tests.integration.helpers.constants import CHARMED_OPERATOR_USERNAME
from tests.integration.helpers.jubilant_common import (
    find_leader,
    get_ip_from_unit,
    get_ips_for_app,
    get_password,
    unit_uri,
    verify_cluster_ip_source_allowlist,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


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

    mongos_uri = unit_uri(CHARMED_OPERATOR_USERNAME, password, ip_address=host, mongos=True)
    return MongoClient(mongos_uri, directConnection=True)


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
