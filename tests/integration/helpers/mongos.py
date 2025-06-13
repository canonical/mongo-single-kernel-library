# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

from juju.unit import Unit as JujuUnit
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    DEPLOYMENT_TIMEOUT,
    MONGOS_APP_NAME,
    MONGOS_PORT,
    deploy_charm,
    get_address_of_unit,
    get_application_relation_data,
    get_secret_data,
    get_unit_id,
    mongosh,
)
from ..helpers.sharding import CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME
from ..helpers.types import Substrate

logger = getLogger(__name__)


MONGOS_CLIENT_APPLICATION = "mongos-test-application"
MONGOS_SOCKET = "%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock"

PING_CMD = "db.runCommand({ping: 1})"

TEST_USER_NAME = "TestUserName1"
TEST_USER_PWD = "Test123"
TEST_DB_NAME = "my-test-db"


async def deploy_cluster_components(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict,
    mongos_resource: dict,
    mongos_client_application_path: str,
    num_units_cluster_config: dict | None = None,
    config_server_name: str = CONFIG_SERVER_APP_NAME,
    shard_one_name: str = SHARD_ONE_APP_NAME,
    mongos_units: int = 1,
) -> None:
    if not num_units_cluster_config:
        num_units_cluster_config = {
            config_server_name: 1,
            shard_one_name: 1,
        }

    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=config_server_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[config_server_name],
        config={"role": "config-server"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=shard_one_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_one_name],
        config={"role": "shard"},
    )
    await deploy_charm(
        ops_test,
        mongos_charm,
        substrate,
        app_name=MONGOS_APP_NAME,
        mongod_resource=mongos_resource,
        num_units=0 if substrate == "lxd" else mongos_units,
    )

    await ops_test.model.deploy(
        mongos_client_application_path,
        application_name=MONGOS_CLIENT_APPLICATION,
        num_units=1,
        series="jammy",
    )

    await ops_test.model.wait_for_idle(
        apps=[config_server_name, shard_one_name, MONGOS_APP_NAME, MONGOS_CLIENT_APPLICATION],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )


async def generate_mongos_uri(
    ops_test: OpsTest,
    substrate: Substrate,
    auth: bool,
    app_name: str,
    external: bool = False,
) -> str:
    """Generates a URI for accessing mongos."""
    mongos_unit = ops_test.model.applications[app_name].units[0]
    mongos_unit_id = get_unit_id(mongos_unit.name)

    host = (
        f"{await get_address_of_unit(ops_test, substrate, mongos_unit_id, app_name)}:{MONGOS_PORT}"
    )
    if not external and substrate == "lxd":
        host = MONGOS_SOCKET

    if not auth:
        return f"mongodb://{host}"

    secret_uri = await get_application_relation_data(ops_test, app_name, "mongos", "secret-user")

    secret_data = await get_secret_data(ops_test, secret_uri)
    return secret_data.get("uris")


async def generate_mongos_command(
    ops_test: OpsTest,
    substrate: Substrate,
    auth: bool,
    app_name: str,
    uri: str | None = None,
    external: bool = False,
) -> str:
    """Generates a command which verifies mongos is running."""
    mongodb_uri = uri or await generate_mongos_uri(ops_test, substrate, auth, app_name, external)
    return f"{mongosh(substrate)} '{mongodb_uri}'  --eval '{PING_CMD}'"


async def check_mongos(
    ops_test: OpsTest,
    substrate: Substrate,
    unit: JujuUnit,
    auth: bool,
    app_name: str,
    uri: str | None = None,
    external: bool = False,
) -> bool:
    """Returns whether mongos is running on the provided unit."""
    mongos_check = await generate_mongos_command(ops_test, substrate, auth, app_name, uri, external)

    # since mongos is communicating only via the unix domain socket, we cannot connect to it via
    # traditional pymongo methods
    ssh_command = (
        ["ssh", "--container", "mongos", unit.name]
        if substrate == "microk8s"
        else ["ssh", unit.name, "sudo"]
    )
    check_cmd = f"{ssh_command} {mongos_check}"
    return_code, stdout, stderr = await ops_test.juju(*check_cmd.split())

    if not return_code == 0:
        logger.warning("check mongos STDOUT=%s, STDERR=%s", stdout, stderr)
    return return_code == 0
