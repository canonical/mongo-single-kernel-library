# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import re
import shutil
import time
import zipfile
from logging import getLogger
from pathlib import Path
from typing import Any

import pytest
from pytest_operator.plugin import OpsTest
from yaml import safe_load

from .helpers.architecture import architecture as _architecture
from .helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    MONGOS_PORT,
    clear_continous_writes,
    deploy_application,
    get_app_name,
    get_direct_mongo_client,
    mongodb_uri,
    relate_mongodb_and_application,
    start_continous_writes,
    stop_continous_writes,
)
from .helpers.sharding import (
    CONFIG_SERVER_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_ONE_COLL_NAME,
    SHARD_ONE_DB_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_TWO_COLL_NAME,
    SHARD_TWO_DB_NAME,
    remove_db_writes,
    write_data_to_mongodb,
)
from .helpers.types import Substrate

logger = getLogger(__name__)


@pytest.fixture(scope="session")
def architecture() -> str:
    return _architecture


@pytest.fixture
def application_path(architecture: str) -> str:
    """The test application path."""
    return f"./tests/integration/applications/continuous_write_charm/continuous-write_ubuntu@24.04-{architecture}.charm"


@pytest.fixture
def client_relation_charm_path(architecture: str) -> str:
    """The test application path."""
    return f"./tests/integration/applications/client_relations_charm/application_ubuntu@24.04-{architecture}.charm"


@pytest.fixture
def mongos_client_application_path(architecture: str) -> str:
    """The mongos test application path."""
    return f"./tests/integration/applications/mongos_client_charm/test-routing-application_ubuntu@24.04-{architecture}.charm"


@pytest.fixture
def mongodb_charm(substrate, mongod_base_path, architecture: str) -> str:
    """The MongoDB charm path, to deploy charms, according to the substrate."""
    if substrate == "microk8s":
        return f"./{mongod_base_path}/mongodb-k8s_ubuntu@24.04-{architecture}.charm"
    return f"./{mongod_base_path}/mongodb_ubuntu@24.04-{architecture}.charm"


@pytest.fixture
def mongos_charm(substrate, mongos_base_path, architecture: str) -> str:
    """The Mongos charm path, to deploy charms, according to the substrate."""
    if substrate == "microk8s":
        return f"./{mongos_base_path}/mongos-k8s_ubuntu@24.04-{architecture}.charm"
    return f"./{mongos_base_path}/mongos_ubuntu@24.04-{architecture}.charm"


@pytest.fixture
def mongod_metadata(mongod_base_path) -> dict[str, Any]:
    """The MongoDB charm metadata."""
    with open(mongod_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongod_resource(mongod_metadata, substrate) -> dict[str, Any]:
    """The MongoDB charm resources for k8s charms."""
    if substrate == "microk8s":
        return {"mongodb-image": mongod_metadata["resources"]["mongodb-image"]["upstream-source"]}
    return {}


@pytest.fixture
def mongos_metadata(mongos_base_path) -> dict[str, Any]:
    """The Mongos charm metadata."""
    with open(mongos_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongos_resource(mongos_metadata, substrate) -> dict[str, Any]:
    """The Mongos charm resources for k8s charms."""
    if substrate == "microk8s":
        return {"mongodb-image": mongos_metadata["resources"]["mongodb-image"]["upstream-source"]}
    return {}


@pytest.fixture
async def continuous_writes_to_db(ops_test: OpsTest, application_path: str):
    """Continuously writget_app_name the duration of the test."""
    db_app_name = await get_app_name(ops_test)
    app_name = CONTINUOUS_WRITE_APPLICATION
    if app_name not in ops_test.model.applications.keys():
        await deploy_application(ops_test, application_path=application_path, app_name=app_name)
        await relate_mongodb_and_application(ops_test, db_app_name, app_name)

    await start_continous_writes(ops_test, app_name)
    yield
    await stop_continous_writes(ops_test, app_name)
    await clear_continous_writes(ops_test, app_name)


@pytest.fixture
async def add_writes_to_db(ops_test: OpsTest, application_path: str):
    """Adds writes to DB before test starts and clears writes at the end of the test."""
    db_app_name = await get_app_name(ops_test)
    app_name = CONTINUOUS_WRITE_APPLICATION
    if app_name not in ops_test.model.applications.keys():
        await deploy_application(ops_test, application_path=application_path, app_name=app_name)
        await relate_mongodb_and_application(ops_test, db_app_name, app_name)

    await start_continous_writes(ops_test, app_name)
    time.sleep(20)
    await stop_continous_writes(ops_test, app_name)
    yield
    await clear_continous_writes(ops_test, app_name)


@pytest.fixture
async def add_writes_to_shard(ops_test: OpsTest, substrate: Substrate, application_path: str):
    """Adds writes to DB before test starts and clears writes at the end of the test."""
    app_name = CONTINUOUS_WRITE_APPLICATION

    if app_name not in ops_test.model.applications.keys():
        await deploy_application(ops_test, application_path=application_path, app_name=app_name)

    # configure write app to use mongos uri
    mongos_uri: str = await mongodb_uri(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, port=MONGOS_PORT
    )
    await ops_test.model.applications[app_name].set_config({"mongos-uri": mongos_uri})

    await start_continous_writes(
        ops_test, app_name, db_name=SHARD_ONE_DB_NAME, coll_name=SHARD_ONE_COLL_NAME
    )
    time.sleep(20)
    await stop_continous_writes(
        ops_test, app_name, db_name=SHARD_ONE_DB_NAME, coll_name=SHARD_ONE_COLL_NAME
    )

    mongos_client = await get_direct_mongo_client(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, mongos=True
    )

    mongos_client.admin.command("movePrimary", SHARD_ONE_DB_NAME, to=SHARD_ONE_APP_NAME)

    write_data_to_mongodb(
        mongos_client,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
        content={"horse-breed": "unicorn", "real": True},
    )

    mongos_client.admin.command("movePrimary", SHARD_TWO_DB_NAME, to=SHARD_TWO_APP_NAME)

    mongos_client.close()

    yield

    mongos_client = await get_direct_mongo_client(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, mongos=True
    )
    remove_db_writes(mongos_client, db_name=SHARD_ONE_DB_NAME, coll_name=SHARD_ONE_COLL_NAME)
    remove_db_writes(mongos_client, db_name=SHARD_TWO_DB_NAME, coll_name=SHARD_TWO_COLL_NAME)
    mongos_client.close()


@pytest.fixture
async def add_continuous_writes_to_shards(
    ops_test: OpsTest, substrate: Substrate, application_path: str
):
    """Generates continuous writes on two shards."""
    app_name = CONTINUOUS_WRITE_APPLICATION

    if app_name not in ops_test.model.applications.keys():
        await deploy_application(ops_test, application_path=application_path, app_name=app_name)
    # configure write app to use mongos uri
    mongos_uri: str = await mongodb_uri(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, port=MONGOS_PORT
    )
    await ops_test.model.applications[app_name].set_config({"mongos-uri": mongos_uri})
    await start_continous_writes(
        ops_test, app_name, db_name=SHARD_ONE_DB_NAME, coll_name=SHARD_ONE_COLL_NAME
    )
    await start_continous_writes(
        ops_test, app_name, db_name=SHARD_TWO_DB_NAME, coll_name=SHARD_TWO_COLL_NAME
    )

    mongos_client = await get_direct_mongo_client(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, mongos=True
    )
    mongos_client.admin.command("movePrimary", SHARD_ONE_DB_NAME, to=SHARD_ONE_APP_NAME)
    mongos_client.admin.command("movePrimary", SHARD_TWO_DB_NAME, to=SHARD_TWO_APP_NAME)
    yield

    await clear_continous_writes(
        ops_test, app_name, db_name=SHARD_ONE_DB_NAME, coll_name=SHARD_ONE_COLL_NAME
    )
    await clear_continous_writes(
        ops_test, app_name, db_name=SHARD_TWO_DB_NAME, coll_name=SHARD_TWO_COLL_NAME
    )


@pytest.fixture
async def faulty_mongodb_upgrade_charm(mongod_base_path: Path, mongodb_charm: str, tmp_path: Path):
    """This fixture builds a mongodb charm that will fail the upgrade.

    It works by updating the workload version and the version of the snap to install.
    That way, it will fail the `refresh_incompatible` check.
    """
    literals_path = "venv/lib/python3.12/site-packages/single_kernel_mongo/config/literals.py"
    fault_charm = f"{tmp_path}/mongodb_fault_charm.charm"
    # Copy the correct charm to a new destination
    shutil.copy(mongodb_charm, fault_charm)

    # What is the current workload version in the charm
    initial_version_path = mongod_base_path / Path("workload_version")
    workload_version = initial_version_path.read_text().strip()

    [major, minor, patch] = workload_version.split(".")

    with zipfile.ZipFile(fault_charm, mode="r") as charm_zip:
        with charm_zip.open(literals_path) as literals_file:
            file_data = literals_file.read().decode().split("\n")

    # What is the revision N of the snap that we're supposed to install if we're a VM charm
    regex = re.compile(r"SNAP.*\(.*, revision=\"([0-9]+)\"\)")

    # Update the read content of the file with a computed value for the snap revision (N - 1)
    for index, line in enumerate(file_data):
        if entry := regex.findall(line):
            current_rev = entry[0]
            new_rev = int(current_rev) - 1
            new_line = line.replace(current_rev, str(new_rev))
            file_data[index] = new_line
            break

    # Update the faulty charm to write the updated values in the correct files
    with zipfile.ZipFile(fault_charm, mode="a") as charm_zip:
        charm_zip.writestr(literals_path, "\n".join(file_data))
        charm_zip.writestr("workload_version", f"{int(major) - 1}.{minor}.{patch}+testrollback")

    yield fault_charm


@pytest.fixture
async def faulty_mongos_upgrade_charm(mongos_base_path: Path, mongos_charm: str, tmp_path: Path):
    """This fixture builds a mongos charm that will fail the upgrade.

    It works by updating the workload version and the version of the snap to install.
    That way, it will fail the `refresh_incompatible` check.
    """
    literals_path = "venv/lib/python3.12/site-packages/single_kernel_mongo/config/literals.py"
    fault_charm = f"{tmp_path}/mongos_fault_charm.charm"
    # Copy the correct charm to a new destination
    shutil.copy(mongos_charm, fault_charm)

    # What is the current workload version in the charm
    initial_version_path = mongos_base_path / Path("workload_version")
    workload_version = initial_version_path.read_text().strip()

    [major, minor, patch] = workload_version.split(".")

    with zipfile.ZipFile(fault_charm, mode="r") as charm_zip:
        with charm_zip.open(literals_path) as literals_file:
            file_data = literals_file.read().decode().split("\n")

    # What is the revision N of the snap that we're supposed to install if we're a VM charm
    regex = re.compile(r"SNAP.*\(.*, revision=\"([0-9]+)\"\)")

    # Update the read content of the file with a computed value for the snap revision (N - 1)
    for index, line in enumerate(file_data):
        if entry := regex.findall(line):
            current_rev = entry[0]
            new_rev = int(current_rev) - 1
            new_line = line.replace(current_rev, str(new_rev))
            file_data[index] = new_line
            break

    # Update the faulty charm to write the updated values in the correct files
    with zipfile.ZipFile(fault_charm, mode="a") as charm_zip:
        charm_zip.writestr(literals_path, "\n".join(file_data))
        charm_zip.writestr("workload_version", f"{int(major) - 1}.{minor}.{patch}+testrollback")

    yield fault_charm
