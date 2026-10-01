# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import random
import string
from copy import deepcopy

import jubilant
from jubilant.statustypes import UnitStatus
from pymongo import MongoClient
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    CONFIG_SERVER_APP_NAME,
    DEFAULT_COLLECTION_NAME,
    DEFAULT_DATABASE_NAME,
    SHARD_APPS,
    SHARD_DEFAULT_COLL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_ONE_DB_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_TWO_COLL_NAME,
    SHARD_TWO_DB_NAME,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    add_juju_secret,
    find_leader,
    get_ip_from_unit,
    get_password,
    unit_uri,
)
from tests.integration.helpers.jubilant_sharding import build_mongos_client, write_data_to_mongodb
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


def get_backup_list(juju: jubilant.Juju, app_name: str) -> str:
    """Count the number of logical backups."""
    leader_unit, _ = find_leader(juju, app_name)
    action = juju.run(leader_unit, "list-backups")
    return action.results["backups"]


def count_logical_backups(juju: jubilant.Juju, unit_name: str) -> int:
    """Count the number of logical backups."""
    task = juju.run(unit_name, action="list-backups")
    list_result = task.results["backups"]
    list_result = list_result.split("\n")
    backups = 0
    for res in list_result:
        if "logical" in res and "in progress" not in res:
            backups += 1

    return backups


def count_failed_backups(juju: jubilant.Juju, unit_name: str) -> int:
    """Count the number of failed backups."""
    task = juju.run(unit_name, action="list-backups")
    list_result = task.results["backups"]
    list_result = list_result.split("\n")
    failed_backups = 0
    for res in list_result:
        failed_backups += 1 if "failed" in res else 0

    return failed_backups


def insert_unwanted_data(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    unit_info: UnitStatus,
    mongos: bool = False,
) -> None:
    """Inserts the data into the MongoDB cluster via primary replica."""
    password = get_password(
        juju=juju,
        app_name=app_name,
        username=CHARMED_OPERATOR_USERNAME,
    )
    ip_address = get_ip_from_unit(substrate=substrate, unit_info=unit_info)

    uri = unit_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=password,
        ip_address=ip_address,
        mongos=mongos,
        replica_set=app_name,
    )

    client = MongoClient(uri, directConnection=True)

    db = client[DEFAULT_DATABASE_NAME]
    test_collection = db[DEFAULT_COLLECTION_NAME]
    test_collection.insert_one({"unwanted_data": "bad data 1"})
    test_collection.insert_one({"unwanted_data": "bad data 2"})
    test_collection.insert_one({"unwanted_data": "bad data 3"})
    client.close()


def create_and_verify_backup(juju: jubilant.Juju, app_name: str) -> None:
    """Creates and verifies that a backup was successfully created."""
    backups = -1
    leader_unit_name, _ = find_leader(juju, app_name=app_name)
    prev_backups = count_logical_backups(juju, leader_unit_name)
    backup = juju.run(leader_unit_name, action="create-backup")
    assert backup.status == "completed", "Backup not started."

    # verify that backup was made on the bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(4), wait=wait_fixed(5)):
            with attempt:
                backups = count_logical_backups(juju, leader_unit_name)
                assert backups == prev_backups + 1, "Backup not created."
    except RetryError:
        assert backups == prev_backups + 1, "Backup not created."


def configure_s3(
    juju: jubilant.Juju,
    app_name: str,
    config: dict[str, str],
    credentials: dict[str, str],
):
    """Configure s3-integrator with bucket/path and other information."""
    logger.info("Adding Juju secret for S3")
    local_label = "".join(random.choice(string.ascii_letters) for _ in range(10))
    credentials_secret_uri = add_juju_secret(
        juju,
        app_name,
        local_label,
        data=credentials,
    )
    logger.info(f"Juju secret for S3 credentials added. Secret URI: {credentials_secret_uri}")

    full_cfg = deepcopy(config)
    full_cfg.update({"credentials": credentials_secret_uri})

    logger.info("Setting up configuration for s3-integrator charm...")
    juju.config(app=app_name, values=full_cfg)
    juju.wait(
        lambda status: are_agents_idle(status, app_name, idle_period=30),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


def configure_gcs(
    juju: jubilant.Juju,
    app_name: str,
    config: dict[str, str],
    credentials: dict[str, str],
):
    """Configure gcs-integrator with bucket/path and service account JSON (via Juju secret)."""
    logger.info("Adding Juju secret for GCS service account JSON")
    local_label = "".join(random.choice(string.ascii_letters) for _ in range(10))
    credentials_secret_uri = add_juju_secret(
        juju,
        app_name,
        local_label,
        {"secret-key": credentials["secret-key"]},
    )
    logger.info(f"Juju secret for GCS credentials added. Secret URI: {credentials_secret_uri}")

    full_cfg = deepcopy(config)
    full_cfg.update({"credentials": credentials_secret_uri})

    logger.info("Setting up configuration for gcs-integrator charm...")
    juju.config(app=app_name, values=full_cfg)
    juju.wait(
        lambda status: are_agents_idle(status, app_name, idle_period=30),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


def count_shard_writes(
    juju: jubilant.Juju,
    substrate: Substrate,
    config_server_name: str,
    db_name: str,
    collection_name: str,
) -> int:
    """Count documents through mongos."""
    client = build_mongos_client(juju, substrate, config_server_name)
    db = client[db_name]
    test_collection = db[collection_name]
    count = test_collection.count_documents({})
    client.close()
    return count


def get_cluster_writes_count(
    juju: jubilant.Juju,
    substrate: Substrate,
    shard_app_names: list[str],
    db_names: list[str],
    config_server_name: str = CONFIG_SERVER_APP_NAME,
) -> dict[str, int]:
    """Returns a dictionary of the writes for each cluster_component and the total writes."""
    cluster_write_count: dict[str, int] = {}
    total_writes = 0
    for app_name in shard_app_names:
        cluster_write_count[app_name] = 0
        for db in db_names:
            component_writes = count_shard_writes(
                juju,
                substrate,
                config_server_name=config_server_name,
                db_name=db,
                collection_name=SHARD_DEFAULT_COLL_NAME,
            )
            cluster_write_count[app_name] += component_writes
            total_writes += component_writes

    cluster_write_count["total_writes"] = total_writes
    return cluster_write_count


def add_and_verify_unwanted_writes(
    juju: jubilant.Juju,
    substrate: Substrate,
    unit_info: UnitStatus,
    old_cluster_writes: dict[str, int],
) -> None:
    """Add writes to all shards that will be cleared after restoring backup.

    Note: this test also verifies every shard has unwanted writes.
    """
    insert_unwanted_data(
        juju, substrate, app_name=CONFIG_SERVER_APP_NAME, unit_info=unit_info, mongos=True
    )

    # new writes added to cluster in `insert_unwanted_data` get sent to shard-one - add more
    # writes to shard-two
    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)
    write_data_to_mongodb(
        mongos_client,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
        content={"horse-breed": "pegasus", "real": True},
    )
    new_total_writes = get_cluster_writes_count(
        juju,
        substrate,
        shard_app_names=SHARD_APPS,
        db_names=[SHARD_ONE_DB_NAME, SHARD_TWO_DB_NAME],
        config_server_name=CONFIG_SERVER_APP_NAME,
    )

    assert (
        new_total_writes["total_writes"] > old_cluster_writes["total_writes"]
    ), "No writes to be cleared after restoring."
    assert (
        new_total_writes[SHARD_ONE_APP_NAME] > old_cluster_writes[SHARD_ONE_APP_NAME]
    ), "No writes to be cleared on shard-one after restoring."
    assert (
        new_total_writes[SHARD_TWO_APP_NAME] > old_cluster_writes[SHARD_TWO_APP_NAME]
    ), "No writes to be cleared on shard-two after restoring."


def verify_writes_restored(
    juju: jubilant.Juju, substrate: Substrate, expected_cluster_writes: dict[str, int]
) -> None:
    """Verify that writes were correctly restored."""
    config_server_name = CONFIG_SERVER_APP_NAME
    shard_one_name = SHARD_ONE_APP_NAME
    shard_two_name = SHARD_TWO_APP_NAME
    shard_apps = [shard_one_name, shard_two_name]

    # verify all writes are present
    restored_total_writes = get_cluster_writes_count(
        juju,
        substrate,
        shard_app_names=shard_apps,
        db_names=[SHARD_ONE_DB_NAME, SHARD_TWO_DB_NAME],
        config_server_name=config_server_name,
    )
    assert (
        restored_total_writes["total_writes"] == expected_cluster_writes["total_writes"]
    ), "writes not correctly restored to whole cluster"
    assert (
        restored_total_writes[shard_one_name] == expected_cluster_writes[shard_one_name]
    ), f"writes not correctly restored to {shard_one_name}"
    assert (
        restored_total_writes[shard_two_name] == expected_cluster_writes[shard_two_name]
    ), f"writes not correctly restored to {shard_two_name}"
