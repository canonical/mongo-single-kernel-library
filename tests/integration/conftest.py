# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import dataclasses
import json
import logging
import os
import shutil
import subprocess
import time
import uuid
import zipfile
from collections.abc import Generator
from logging import getLogger
from pathlib import Path
from platform import machine
from typing import Any

import boto3
import botocore.exceptions
import pytest
import tomli
import tomli_w
from pytest_operator.plugin import OpsTest
from yaml import safe_load

from tests.integration.helpers.architecture import architecture as _architecture
from tests.integration.helpers.backups import CloudConfigs, CloudConfiguration
from tests.integration.helpers.common import (
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
from tests.integration.helpers.sharding import (
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
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


@pytest.fixture(scope="session")
def architecture() -> str:
    return _architecture


@pytest.fixture(scope="session")
def mongodb_revision(request: pytest.FixtureRequest) -> int:
    """Revision for the correct arch."""
    return int(request.config.option.mongodb_revision)


@pytest.fixture(scope="session")
def mongos_revision(request: pytest.FixtureRequest):
    """Revision for the correct arch."""
    return int(request.config.option.mongos_revision)


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
def mongodb_charm_name(substrate: Substrate) -> str:
    return "mongodb" if substrate == "lxd" else "mongodb-k8s"


@pytest.fixture
def mongos_charm_name(substrate: Substrate) -> str:
    return "mongos" if substrate == "lxd" else "mongos-k8s"


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
    fault_charm = f"{tmp_path}/mongodb_fault_charm.charm"
    # Copy the correct charm to a new destination
    shutil.copy(mongodb_charm, fault_charm)

    # What is the current workload version in the charm
    initial_version_path = mongod_base_path / Path("refresh_versions.toml")
    initial_version_data = tomli.loads(initial_version_path.read_text().strip())
    workload_version = initial_version_data["workload"]
    snap_revision = initial_version_data.get("snap", {}).get("revisions", {}).get(machine())

    [major, minor, patch] = workload_version.split(".")
    initial_version_data["workload"] = f"{int(major) - 1}.{minor}.{patch}+testrollback"
    new_snap_revision = int(snap_revision) - 1 if snap_revision else None

    with zipfile.ZipFile(fault_charm, mode="r") as charm_zip:
        with charm_zip.open("refresh_versions.toml") as versions_file:
            file_data = versions_file.read().decode()

    versions = tomli.loads(file_data)

    versions["workload"] = f"{int(major) - 1}.{minor}.{patch}+testrollback"
    versions["charm"] = "test/0.1.0+dirty"
    if new_snap_revision:
        versions["snap"]["revisions"][machine()] = f"{new_snap_revision}"

    # Update the faulty charm to write the updated values in the correct files
    with zipfile.ZipFile(fault_charm, mode="a") as charm_zip:
        charm_zip.writestr("refresh_versions.toml", tomli_w.dumps(versions))

    yield fault_charm


@pytest.fixture
async def faulty_mongos_upgrade_charm(mongos_base_path: Path, mongos_charm: str, tmp_path: Path):
    """This fixture builds a mongos charm that will fail the upgrade.

    It works by updating the workload version and the version of the snap to install.
    That way, it will fail the `refresh_incompatible` check.
    """
    fault_charm = f"{tmp_path}/mongos_fault_charm.charm"

    # Copy the correct charm to a new destination
    shutil.copy(mongos_charm, fault_charm)

    # What is the current workload version in the charm
    initial_version_path = mongos_base_path / Path("refresh_versions.toml")
    initial_version_data = tomli.loads(initial_version_path.read_text().strip())
    workload_version = initial_version_data["workload"]
    snap_revision = initial_version_data.get("snap", {}).get("revisions", {}).get(machine())

    [major, minor, patch] = workload_version.split(".")
    initial_version_data["workload"] = f"{int(major) - 1}.{minor}.{patch}+testrollback"
    new_snap_revision = int(snap_revision) - 1 if snap_revision else None

    with zipfile.ZipFile(fault_charm, mode="r") as charm_zip:
        with charm_zip.open("refresh_versions.toml") as versions_file:
            file_data = versions_file.read().decode()

    versions = tomli.loads(file_data)

    versions["workload"] = f"{int(major) - 1}.{minor}.{patch}+testrollback"
    versions["charm"] = "test/0.1.0+dirty"
    if new_snap_revision:
        versions["snap"]["revisions"][machine()] = f"{new_snap_revision}"

    # Update the faulty charm to write the updated values in the correct files
    with zipfile.ZipFile(fault_charm, mode="a") as charm_zip:
        charm_zip.writestr("refresh_versions.toml", tomli_w.dumps(versions))
    yield fault_charm


@dataclasses.dataclass(frozen=True)
class ConnectionInformation:
    access_key_id: str
    secret_access_key: str
    bucket: str


@pytest.fixture(scope="session")
def microceph() -> ConnectionInformation:
    """Deploy microceph with rados-gateway and provide the credentials to access it."""
    if not os.environ.get("CI") == "true":
        raise Exception("Not running on CI. Skipping microceph installation. ")
    logger.info("Setting up microceph")

    # socket.gethostbyname() might return `127.0.0.1`, which does not work from
    # inside lxd container
    host_ip = (
        subprocess.run(["hostname", "-I"], capture_output=True, check=True, encoding="utf-8")
        .stdout.strip()
        .split()[0]
    )

    subprocess.run(["sudo", "snap", "install", "microceph"], check=True)
    subprocess.run(["sudo", "microceph", "cluster", "bootstrap"], check=True)
    subprocess.run(["sudo", "microceph", "disk", "add", "loop,4G,3"], check=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-sha256",
            "-days",
            "365",
            "-nodes",
            "-subj",
            f"/CN={host_ip}",
            "-addext",
            f"subjectAltName=IP:{host_ip}",
        ],
        check=True,
    )

    with open("cert.pem", "rb") as cert_file:
        cert = cert_file.read()
        cert_encoded = base64.b64encode(cert)

    with open("key.pem", "rb") as key_file:
        key = key_file.read()
        key_encoded = base64.b64encode(key)

    subprocess.run(
        [
            "sudo",
            "microceph",
            "enable",
            "rgw",
            "--ssl-port",
            "445",
            "--ssl-certificate",
            cert_encoded,
            "--ssl-private-key",
            key_encoded,
        ],
        check=True,
    )
    output = subprocess.run(
        [
            "sudo",
            "microceph.radosgw-admin",
            "user",
            "create",
            "--uid",
            "test",
            "--display-name",
            "test",
        ],
        capture_output=True,
        check=True,
        encoding="utf-8",
    ).stdout
    key = json.loads(output)["keys"][0]
    key_id = key["access_key"]
    secret_key = key["secret_key"]
    logger.info("Creating microceph bucket")
    for attempt in range(3):
        try:
            boto3.client(
                "s3",
                endpoint_url=f"https://{host_ip}:445",
                aws_access_key_id=key_id,
                aws_secret_access_key=secret_key,
                verify="cert.pem",
            ).create_bucket(Bucket=_BUCKET)
        except botocore.exceptions.EndpointConnectionError:
            if attempt == 2:
                raise
            # microceph is not ready yet
            logger.info("Unable to connect to microceph via S3. Retrying")
            time.sleep(1)
        else:
            break
    logger.info("Set up microceph")
    return ConnectionInformation(key_id, secret_key, _BUCKET)


_BUCKET = "testbucket"
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def storage_config(microceph: ConnectionInformation) -> dict[str, str]:
    """Provide the configuration required by s3-integrator."""
    # socket.gethostbyname() might return `127.0.0.1`, which does not work from
    # inside lxd container
    host_ip = (
        subprocess.run(["hostname", "-I"], capture_output=True, check=True, encoding="utf-8")
        .stdout.strip()
        .split()[0]
    )

    with open("cert.pem", "rb") as cert_file:
        cert = cert_file.read()
        cert_encoded = base64.b64encode(cert).decode("utf-8")

    return {
        "endpoint": f"https://{host_ip}:445",
        "bucket": microceph.bucket,
        "path": "mongodb-backups",
        "region": "",
        "tls-ca-chain": cert_encoded,
    }


@pytest.fixture(scope="session")
def storage_credentials(microceph: ConnectionInformation) -> dict[str, str]:
    """Provide the access-credentials required by s3-integrator."""
    return {
        "access-key": microceph.access_key_id,
        "secret-key": microceph.secret_access_key,
    }


@pytest.fixture(scope="function")
def s3_bucket(storage_credentials, storage_config) -> None:
    """Provide a storage bucket on the deployed microceph instance."""
    session = boto3.Session(
        aws_access_key_id=storage_credentials["access-key"],
        aws_secret_access_key=storage_credentials["secret-key"],
        region_name=storage_config["region"] if storage_config["region"] else None,
    )
    s3 = session.resource("s3", endpoint_url=storage_config["endpoint"], verify="cert.pem")
    bucket = s3.Bucket(storage_config["bucket"])
    yield bucket


@pytest.fixture(scope="session")
def cloud_configs_aws(substrate: Substrate) -> CloudConfiguration:
    path = "mongodb-vm" if substrate == "lxd" else "mongodb-k8s"
    configs: dict[str, str] = {
        "endpoint": "https://s3.amazonaws.com",
        "bucket": "data-charms-testing",
        "path": f"{path}/{uuid.uuid4()}",
        "region": "us-east-1",
    }
    credentials: dict[str, str] = {
        "access-key": os.environ["AWS_ACCESS_KEY"],
        "secret-key": os.environ["AWS_SECRET_KEY"],
    }
    return configs, credentials


@pytest.fixture(scope="session")
def cloud_configs_gcp(substrate: Substrate) -> CloudConfiguration:
    path = "mongodb-vm" if substrate == "lxd" else "mongodb-k8s"
    configs: dict[str, str] = {
        "bucket": "data-charms-testing",
        "endpoint": "https://storage.googleapis.com",
        "region": "",
        "path": f"{path}/{uuid.uuid4()}",
    }
    credentials: dict[str, str] = {
        "access-key": os.environ["GCP_ACCESS_KEY"],
        "secret-key": os.environ["GCP_SECRET_KEY"],
    }
    return configs, credentials


@pytest.fixture(scope="session")
def cloud_configs_gcs(substrate: Substrate) -> CloudConfiguration:
    path = "mongodb-vm" if substrate == "lxd" else "mongodb-k8s"
    configs: dict[str, str] = {
        "bucket": "data-charms-testing",
        "path": f"{path}/{uuid.uuid4()}",
    }
    credentials: dict[str, str] = {
        "secret-key": os.environ["GCS_SERVICE_ACCOUNT"],
    }
    return configs, credentials


@pytest.fixture(scope="session")
def cloud_configs(
    cloud_configs_gcp: CloudConfiguration,
    cloud_configs_aws: CloudConfiguration,
    cloud_configs_gcs: CloudConfiguration,
) -> Generator[CloudConfigs]:
    yield {"AWS": cloud_configs_aws, "GCP": cloud_configs_gcp, "GCS": cloud_configs_gcs}
