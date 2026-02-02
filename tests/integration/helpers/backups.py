# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import random
import string
from copy import deepcopy

from juju.unit import Unit as JujuUnit
from pymongo import MongoClient
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

from ..helpers.common import (
    DEFAULT_COLLECTION_NAME,
    DEFAULT_DATABASE_NAME,
    TIMEOUT,
    add_juju_secret,
    find_unit,
    generate_mongodb_client,
    get_address_of_unit,
    get_unit_id,
)
from ..helpers.types import Substrate

S3_APP_NAME = "s3-integrator"
S3_ENDPOINT = "s3-credentials"
GCS_APP_NAME = "gcs-integrator"
GCS_ENDPOINT = "gcs-credentials"

NEW_CLUSTER = "new-mongodb"

CloudConfiguration = tuple[dict[str, str], dict[str, str]]
CloudConfigs = dict[str, CloudConfiguration]


logger = logging.getLogger(__name__)


async def set_credentials(
    ops_test: OpsTest,
    cloud_configs: CloudConfigs,
    cloud: str,
    app_name: str,
) -> None:
    """Sets the s3 crednetials for the provided cloud, valid options are AWS or GCP."""
    _, cloud_credentials = cloud_configs[cloud]
    # set access key and secret keys
    assert (
        cloud_credentials["access-key"] and cloud_credentials["secret-key"]
    ), f"{cloud} access key and secret key not provided."

    s3_integrator_unit = ops_test.model.applications[app_name].units[0]
    action = await s3_integrator_unit.run_action(
        action_name="sync-s3-credentials", **cloud_credentials
    )
    await action.wait()


async def get_backup_list(ops_test: OpsTest, app_name: str | None = None) -> str:
    """Count the number of logical backups."""
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    return list_result.results["backups"]


async def count_logical_backups(db_unit: JujuUnit) -> int:
    """Count the number of logical backups."""
    action = await db_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    list_result = list_result.split("\n")
    backups = 0
    for res in list_result:
        backups += 1 if "logical" in res else 0

    return backups


async def count_failed_backups(db_unit: JujuUnit) -> int:
    """Count the number of failed backups."""
    action = await db_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    list_result = list_result.split("\n")
    failed_backups = 0
    for res in list_result:
        failed_backups += 1 if "failed" in res else 0

    return failed_backups


async def insert_unwanted_data(
    ops_test: OpsTest, substrate: Substrate, app_name: str, unit: JujuUnit, mongos: bool = False
) -> None:
    """Inserts the data into the MongoDB cluster via primary replica."""
    host = await get_address_of_unit(ops_test, substrate, get_unit_id(unit.name), app_name=app_name)
    uri = await generate_mongodb_client(ops_test, substrate, app_name, mongos=mongos, hosts=[host])

    client = MongoClient(uri, directConnection=True)

    db = client[DEFAULT_DATABASE_NAME]
    test_collection = db[DEFAULT_COLLECTION_NAME]
    test_collection.insert_one({"unwanted_data": "bad data 1"})
    test_collection.insert_one({"unwanted_data": "bad data 2"})
    test_collection.insert_one({"unwanted_data": "bad data 3"})
    client.close()


async def create_and_verify_backup(ops_test: OpsTest, app_name: str) -> None:
    """Creates and verifies that a backup was successfully created."""
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    prev_backups = await count_logical_backups(leader_unit)
    action = await leader_unit.run_action(action_name="create-backup")
    backup = await action.wait()
    assert backup.status == "completed", "Backup not started."

    # verify that backup was made on the bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(4), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == prev_backups + 1, "Backup not created."
    except RetryError:
        assert backups == prev_backups + 1, "Backup not created."


async def configure_gcs(
    ops_test: OpsTest,
    config: dict[str, str],
    credentials: dict[str, str],
):
    """Configure gcs-integrator with bucket/path and service account JSON (via Juju secret)."""
    logger.info("Adding Juju secret for GCS service account JSON")
    local_label = "".join(random.choice(string.ascii_letters) for _ in range(10))
    credentials_secret_uri = await add_juju_secret(
        ops_test,
        GCS_APP_NAME,
        local_label,
        {"secret-key": credentials["secret-key"]},
    )
    logger.info(f"Juju secret for GCS credentials added. Secret URI: {credentials_secret_uri}")

    full_cfg = deepcopy(config)
    full_cfg.update({"credentials": credentials_secret_uri})

    logger.info("Setting up configuration for gcs-integrator charm...")
    await ops_test.model.applications[GCS_APP_NAME].set_config(full_cfg)
    await ops_test.model.wait_for_idle(apps=[GCS_APP_NAME], timeout=TIMEOUT)
