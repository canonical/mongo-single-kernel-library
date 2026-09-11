#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import jubilant
from jubilant.statustypes import UnitStatus
from pymongo.synchronous.mongo_client import MongoClient

from tests.integration.helpers.common import (
    external_cert_path,
)
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    DEFAULT_COLLECTION_NAME,
    DEFAULT_DATABASE_NAME,
)
from tests.integration.helpers.jubilant_common import (
    get_ip_from_unit,
    get_password,
    scp_file_preserve_ctime,
    unit_uri,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


def start_continuous_writes(
    juju: jubilant.Juju,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
):
    """Helper function to run the `start-continuous-write` action on the continuous write app."""
    juju.run(
        f"{client_app_name}/0",
        "start-continuous-writes",
        {"db-name": db_name, "collection-name": coll_name},
    )


def start_continuous_reads(
    juju: jubilant.Juju,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
):
    """Helper function to run the `start-continuous-reads` action on the continuous write app."""
    juju.run(
        f"{client_app_name}/0",
        "start-continuous-reads",
        {"db-name": db_name, "collection-name": coll_name},
    )


def stop_continuous_writes(
    juju: jubilant.Juju,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
):
    """Helper function to run the `stop-continuous-writes` action on the continuous write app."""
    juju.run(
        f"{client_app_name}/0",
        "stop-continuous-writes",
        {"db-name": db_name, "collection-name": coll_name},
    )


def stop_continuous_reads(
    juju: jubilant.Juju,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
) -> tuple[int, list[str]]:
    """Helper function to run the `stop-continuous-reads` action on the continuous write app."""
    result = juju.run(
        f"{client_app_name}/0",
        "stop-continuous-reads",
        {"db-name": db_name, "collection-name": coll_name},
    )
    logger.warning(f"Failed reads: {result.results['failed-reads']}")
    return int(result.results["reads"]), result.results["failed-reads"]


def clear_continuous_writes(
    juju: jubilant.Juju,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
):
    """Helper function to run the `clear-continuous-writes` action on the continuous write app."""
    juju.run(
        f"{client_app_name}/0",
        "clear-continuous-writes",
        {"db-name": db_name, "collection-name": coll_name},
    )


def count_writes(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    unit_name: str,
    unit_info: UnitStatus,
    mongos: bool = False,
    username: str = CHARMED_OPERATOR_USERNAME,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
    tls: bool = False,
    container: str = "mongod",
) -> int:
    """Count the number of writes written on a specific column and database."""
    host = get_ip_from_unit(substrate, unit_info)
    password = get_password(juju, app_name=app_name, username=username)
    uri = unit_uri(username, password, host, replica_set=app_name, mongos=mongos)

    if tls:
        ca_file = scp_file_preserve_ctime(
            juju, substrate, unit_name, external_cert_path(substrate), container
        )
    else:
        ca_file = None

    client = MongoClient(uri, directConnection=True, tlsCaFile=ca_file, tls=tls)
    db = client[db_name]
    test_collection = db[coll_name]
    count = test_collection.count_documents({})
    client.close()

    if ca_file:
        Path(ca_file).unlink()
    return count
