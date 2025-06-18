# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

from juju.unit import Unit as JujuUnit
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    DEPLOYMENT_TIMEOUT,
    MONGOS_APP_NAME,
    MONGOS_PORT,
    TIMEOUT,
    deploy_charm,
    get_address_of_unit,
    get_application_relation_data,
    get_secret_data,
    get_unit_id,
    mongosh,
    wait_for_mongodb_units_blocked,
)
from ..helpers.sharding import (
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
)
from ..helpers.tls import (
    SNAP_MONGOS_SERVICE,
    TLS_CERTIFICATES_APP_NAME,
    TLS_RELATION_NAME,
    check_certs_correctly_distributed,
    check_tls,
    external_cert_path,
    get_file_content,
    internal_cert_path,
    time_file_created,
    time_process_started,
)
from ..helpers.types import Substrate

logger = getLogger(__name__)

MONGOS_CLUSTER_COMPONENTS = [CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME]

MONGOS_CLIENT_APPLICATION = "test-routing-application"
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
    channel: str | None = None,
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
        channel=channel,
    )

    await ops_test.model.deploy(
        mongos_client_application_path,
        application_name=MONGOS_CLIENT_APPLICATION,
        num_units=1,
        series="jammy",
    )

    apps_to_wait_for = [config_server_name, shard_one_name, MONGOS_CLIENT_APPLICATION]
    if substrate == "microk8s":
        apps_to_wait_for.append(MONGOS_APP_NAME)

    await ops_test.model.wait_for_idle(
        apps=apps_to_wait_for,
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )


async def build_cluster(
    ops_test: OpsTest, substrate: Substrate, integrate_with_mongos: bool = True
) -> None:
    """Connects the cluster components to each other."""
    await ops_test.model.integrate(MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME)
    await wait_for_mongodb_units_blocked(
        ops_test, substrate, MONGOS_APP_NAME, timeout=TIMEOUT, subordinate=(substrate == "lxd")
    )

    # prepare sharded cluster
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME],
        idle_period=10,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    apps = [CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME]
    if integrate_with_mongos:
        # connect sharded cluster to mongos
        await ops_test.model.integrate(
            f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
            f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
        )
        apps.append(MONGOS_APP_NAME)

    await ops_test.model.wait_for_idle(
        apps=apps,
        idle_period=20,
        status="active",
        timeout=TIMEOUT,
    )


async def integrate_cluster_with_tls(ops_test: OpsTest) -> None:
    """Integrate cluster components to the TLS interface."""
    for cluster_component in MONGOS_CLUSTER_COMPONENTS:
        await ops_test.model.integrate(
            f"{cluster_component}:{TLS_RELATION_NAME}",
            f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
        )

    await ops_test.model.wait_for_idle(
        apps=MONGOS_CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
        status="active",
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

    if not external and substrate == "lxd":
        host = MONGOS_SOCKET
    elif external and substrate == "lxd":
        host = f"{await mongos_unit.get_public_address()}:{MONGOS_PORT}"
    else:
        host = f"{await get_address_of_unit(ops_test, substrate, mongos_unit_id, app_name)}:{MONGOS_PORT}"

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
    cmd: str = PING_CMD,
) -> str:
    """Generates a command which verifies mongos is running."""
    mongodb_uri = uri or await generate_mongos_uri(ops_test, substrate, auth, app_name, external)
    return f"{mongosh(substrate)} '{mongodb_uri}'  --eval '{cmd}'"


async def check_mongos(
    ops_test: OpsTest,
    substrate: Substrate,
    unit: JujuUnit,
    auth: bool,
    app_name: str,
    uri: str | None = None,
    external: bool = False,
    cmd: str = PING_CMD,
) -> bool:
    """Returns whether mongos is running on the provided unit."""
    mongos_check = await generate_mongos_command(
        ops_test, substrate, auth, app_name, uri, external, cmd
    )

    # since mongos is communicating only via the unix domain socket, we cannot connect to it via
    # traditional pymongo methods
    ssh_command = " ".join(
        ["ssh", "--container", "mongos", unit.name]
        if substrate == "microk8s"
        else ["ssh", unit.name, "sudo"]
    )
    check_cmd = f"{ssh_command} {mongos_check}"
    return_code, stdout, stderr = await ops_test.juju(*check_cmd.split())

    if not return_code == 0:
        logger.warning("check mongos STDOUT=%s, STDERR=%s", stdout, stderr)
    return return_code == 0


async def check_mongos_tls_enabled(ops_test: OpsTest, substrate: Substrate):
    # check mongos is running with TLS enabled
    for unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        await check_tls(
            ops_test,
            substrate,
            unit,
            app_name=MONGOS_APP_NAME,
            enabled=False,
            mongos=True,
            container="mongos",
        )


async def check_mongos_tls_disabled(ops_test: OpsTest, substrate: Substrate) -> None:
    # check mongos is running with TLS enabled
    for unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        await check_tls(
            ops_test, substrate, unit, app_name=MONGOS_APP_NAME, enabled=False, container="mongos"
        )


async def rotate_and_verify_certs(ops_test: OpsTest, substrate: Substrate, app_name: str) -> None:
    """Verify provided app can rotate its TLS certs."""
    original_tls_info = {}

    ext_cert_path = external_cert_path(substrate)
    int_cert_path = internal_cert_path(substrate)

    for unit in ops_test.model.applications[app_name].units:
        original_tls_info[unit.name] = {}
        original_tls_info[unit.name]["external_cert_contents"] = await get_file_content(
            ops_test, substrate, unit.name, ext_cert_path, container="mongos"
        )
        original_tls_info[unit.name]["internal_cert_contents"] = await get_file_content(
            ops_test, substrate, unit.name, int_cert_path, container="mongos"
        )
        original_tls_info[unit.name]["external_cert"] = await time_file_created(
            ops_test, substrate, unit.name, ext_cert_path
        )
        original_tls_info[unit.name]["internal_cert"] = await time_file_created(
            ops_test, substrate, unit.name, int_cert_path
        )
        original_tls_info[unit.name]["mongos_service"] = await time_process_started(
            ops_test, substrate, unit.name, SNAP_MONGOS_SERVICE
        )
        await check_certs_correctly_distributed(ops_test, substrate, app_name=app_name, unit=unit)

    # set external and internal key using auto-generated key for each unit
    for unit in ops_test.model.applications[app_name].units:
        action = await unit.run_action(action_name="set-tls-private-key")
        action = await action.wait()
        assert action.status == "completed", "setting external and internal key failed."

    # wait for certificate to be available and processed. Can get receive two certificate
    # available events and restart twice so we want to ensure we are idle for at least 1 minute
    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, idle_period=60
    )

    # After updating both the external key and the internal key a new certificate request will be
    # made; then the certificates should be available and updated.
    for unit in ops_test.model.applications[app_name].units:
        new_external_cert = await get_file_content(
            ops_test, substrate, unit.name, ext_cert_path, container="mongos"
        )
        new_internal_cert = await get_file_content(
            ops_test, substrate, unit.name, int_cert_path, container="mongos"
        )
        new_external_cert_time = await time_file_created(
            ops_test, substrate, unit.name, ext_cert_path
        )
        new_internal_cert_time = await time_file_created(
            ops_test, substrate, unit.name, int_cert_path
        )
        new_mongos_service_time = await time_process_started(
            ops_test, substrate, unit.name, SNAP_MONGOS_SERVICE
        )

        await check_certs_correctly_distributed(ops_test, substrate, app_name=app_name, unit=unit)
        assert (
            new_external_cert != original_tls_info[unit.name]["external_cert_contents"]
        ), "external cert not rotated"

        assert (
            new_internal_cert != original_tls_info[unit.name]["external_cert_contents"]
        ), "external cert not rotated"
        assert (
            new_external_cert_time > original_tls_info[unit.name]["external_cert"]
        ), f"external cert for {unit.name} was not updated."
        assert (
            new_internal_cert_time > original_tls_info[unit.name]["internal_cert"]
        ), f"internal cert for {unit.name} was not updated."

        # Once the certificate requests are processed and updated the .service file should be
        # restarted
        assert (
            new_mongos_service_time > original_tls_info[unit.name]["mongos_service"]
        ), f"mongod service for {unit.name} was not restarted."

    # Verify that TLS is functioning on all units.
    await check_mongos_tls_enabled(ops_test, substrate)


async def toggle_tls_mongos(
    ops_test: OpsTest, enable: bool, certs_app_name: str = TLS_CERTIFICATES_APP_NAME
) -> None:
    """Toggles TLS on mongos application to the specified enabled state."""
    if enable:
        await ops_test.model.integrate(
            f"{MONGOS_APP_NAME}:{TLS_RELATION_NAME}",
            f"{certs_app_name}:{TLS_RELATION_NAME}",
        )
    else:
        await ops_test.model.applications[MONGOS_APP_NAME].remove_relation(
            f"{MONGOS_APP_NAME}:{TLS_RELATION_NAME}",
            f"{certs_app_name}:{TLS_RELATION_NAME}",
        )
