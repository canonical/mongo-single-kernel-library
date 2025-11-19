# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import subprocess
from logging import getLogger

from juju.unit import Unit as JujuUnit
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    DATA_INTEGRATOR_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    MONGOS_APP_NAME,
    MONGOS_PORT,
    TIMEOUT,
    deploy_charm,
    find_unit,
    get_address_of_unit,
    get_application_relation_data,
    get_relation_username_password,
    get_secret_data,
    get_unit_hostnames,
    get_unit_id,
    mongosh,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.tls import (
    SNAP_MONGOS_SERVICE,
    TLS_CERTIFICATES_APP_NAME,
    TLS_RELATION_NAME,
    check_certs_correctly_distributed,
    check_tls,
    external_cert_path,
    get_file_content,
    internal_cert_path,
    set_private_keys,
    time_file_created,
    time_process_started,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)

CLUSTER_REL_NAME = "cluster"
CONFIG_SERVER_APP_NAME = "config-server"
CONFIG_SERVER_REL_NAME = "config-server"
SHARD_ONE_APP_NAME = "shard-one"
SHARD_REL_NAME = "sharding"
MONGOS_CLUSTER_COMPONENTS = [CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME]

MONGOS_CLIENT_APPLICATION = "test-routing-application"
MONGOS_SOCKET = "%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock"

PING_CMD = "db.runCommand({ping: 1})"

TEST_USER_NAME = "TestUserName1"
TEST_USER_PWD = "Test123"
TEST_DB_NAME = "my-test-db"

MONGOS_RELATION = "mongos_proxy"
CLIENT_RELATION = "mongodb"

PORT_MAPPING_INDEX = 4


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
    """Deploys the cluster components.

    This includes: a config server, a shard, a mongos application, and a mongos client application.
    It then waits for everything to be idle.
    """
    if not num_units_cluster_config:
        num_units_cluster_config = {
            config_server_name: 1,
            shard_one_name: 1,
        }

    if channel is not None:
        mongos_charm = "mongos" if substrate == "lxd" else "mongos-k8s"

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
        num_units=mongos_units,
        series="noble",
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
    ops_test: OpsTest,
    substrate: Substrate,
    integrate_with_mongos: bool = True,
    integrate_with_client: bool = True,
) -> None:
    """Connects the cluster components to each other."""
    if integrate_with_client:
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
    mongos_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    mongos_unit_id = get_unit_id(mongos_unit.name)

    if not external and substrate == "lxd":
        host = MONGOS_SOCKET
    elif external and substrate == "lxd":
        host = f"{await mongos_unit.get_public_address()}:{MONGOS_PORT}"
    else:
        host = f"{await get_address_of_unit(ops_test, substrate, mongos_unit_id, app_name)}:{MONGOS_PORT}"

    if not auth:
        return f"mongodb://{host}"

    if substrate == "lxd":
        rel_name = "mongos"
    else:
        rel_name = "mongodb"

    secret_uri = await get_application_relation_data(ops_test, app_name, rel_name, "secret-user")
    assert secret_uri, "No secret uri found."

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


async def exec_on_mongos(
    ops_test: OpsTest,
    substrate: Substrate,
    unit: JujuUnit,
    auth: bool,
    app_name: str,
    cmd: str,
    uri: str | None = None,
    external: bool = False,
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

    logger.info("ret_code: %s, stdout: %s, stderr: %s", return_code, stdout, stderr)

    if not return_code == 0:
        logger.warning(f"Failed to execute {mongos_check}: {stderr=}, {stdout=}")

    return return_code == 0


async def is_mongos_running(
    ops_test: OpsTest,
    substrate: Substrate,
    unit: JujuUnit,
    auth: bool,
    app_name: str,
    uri: str | None = None,
    external: bool = False,
) -> bool:
    """Checks that mongos is running by executing the ping command."""
    return await exec_on_mongos(ops_test, substrate, unit, auth, app_name, PING_CMD, uri, external)


async def get_external_uri(ops_test: OpsTest, unit: JujuUnit) -> str:
    """Builds the internal uri for mongos."""
    unit_id = get_unit_id(unit.name)
    exposed_node_port = get_port_from_node_port(
        ops_test, node_port_name=f"{MONGOS_APP_NAME}-{unit_id}"
    )
    public_k8s_ip = get_k8s_public_ip()
    username, password = await get_relation_username_password(ops_test, MONGOS_APP_NAME, "cluster")
    return f"mongodb://{username}:{password}@{public_k8s_ip}:{exposed_node_port}"


async def assert_mongos_tls_enabled(ops_test: OpsTest, substrate: Substrate, internal: bool = True):
    # check mongos is running with TLS enabled
    for unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        uri = (
            await get_external_uri(ops_test, unit)
            if not internal
            else await generate_mongos_uri(
                ops_test,
                substrate,
                auth=True,
                app_name=MONGOS_CLIENT_APPLICATION,
                external=not internal,
            )
        )
        assert await check_tls(
            ops_test,
            substrate,
            unit,
            app_name=MONGOS_APP_NAME,
            enabled=True,
            mongos=True,
            container="mongos",
            uri=uri,
        ), f"TLS not enabled on {unit.name}"


async def assert_mongos_tls_disabled(
    ops_test: OpsTest, substrate: Substrate, internal: bool = True
) -> None:
    # check mongos is running with TLS enabled
    for unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        uri = (
            await get_external_uri(ops_test, unit)
            if not internal
            else await generate_mongos_uri(
                ops_test,
                substrate,
                auth=True,
                app_name=MONGOS_CLIENT_APPLICATION,
                external=not internal,
            )
        )
        assert await check_tls(
            ops_test,
            substrate,
            unit,
            app_name=MONGOS_APP_NAME,
            enabled=False,
            container="mongos",
            uri=uri,
        ), f"TLS still enabled on {unit.name}"


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
            ops_test, substrate, unit.name, ext_cert_path, container="mongos"
        )
        original_tls_info[unit.name]["internal_cert"] = await time_file_created(
            ops_test, substrate, unit.name, int_cert_path, container="mongos"
        )
        original_tls_info[unit.name]["mongos_service"] = await time_process_started(
            ops_test, substrate, unit.name, SNAP_MONGOS_SERVICE, container="mongos"
        )
        await check_certs_correctly_distributed(
            ops_test, substrate, app_name=app_name, unit=unit, container="mongos"
        )

    await set_private_keys(ops_test, app_name)

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
            ops_test, substrate, unit.name, ext_cert_path, container="mongos"
        )
        new_internal_cert_time = await time_file_created(
            ops_test, substrate, unit.name, int_cert_path, container="mongos"
        )
        new_mongos_service_time = await time_process_started(
            ops_test, substrate, unit.name, SNAP_MONGOS_SERVICE, container="mongos"
        )

        await check_certs_correctly_distributed(
            ops_test, substrate, app_name=app_name, unit=unit, container="mongos"
        )
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
    await assert_mongos_tls_enabled(ops_test, substrate)


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


def get_k8s_public_ip() -> str:
    """Gets the public IP exposed by kubernetes.

    This is used when we're testing for external connection.
    """
    result = subprocess.run("kubectl get nodes -o json", shell=True, capture_output=True, text=True)

    if result.returncode:
        logger.info("failed to retrieve public facing k8s IP error: %s", result.stderr)
        assert False, "failed to retrieve public facing k8s IP"

    node_info = json.loads(result.stdout)

    try:
        return node_info["items"][0]["status"]["addresses"][0]["address"]
    except KeyError:
        assert False, "failed to retrieve public facing k8s IP"


def get_node_port_info(ops_test: OpsTest, node_port_name: str) -> subprocess.CompletedProcess:
    """Gets the node port information.

    This is used when we're testing for external connection.
    """
    node_port_cmd = (
        f"kubectl get svc  -n  {ops_test.model.name} |  grep NodePort | grep {node_port_name}"
    )
    return subprocess.run(node_port_cmd, shell=True, capture_output=True, text=True)


def has_node_port(ops_test: OpsTest, node_port_name: str) -> bool:
    """Checks if the node has a node port enabled."""
    result = get_node_port_info(ops_test, node_port_name)
    return len(result.stdout.splitlines()) > 0


def get_port_from_node_port(ops_test: OpsTest, node_port_name: str) -> str:
    """Gets the port from the node port information."""
    result = get_node_port_info(ops_test, node_port_name)

    assert len(result.stdout.splitlines()) > 0, "No port information available for expected service"

    # port information is available at PORT_MAPPING_INDEX
    port_mapping = result.stdout.split()[PORT_MAPPING_INDEX]

    # port information is of the form 27018:30259/TCP
    return port_mapping.split(":")[1].split("/")[0]


def assert_node_port_availablity(
    ops_test: OpsTest, node_port_name: str, available: bool = True
) -> None:
    """Checks the availability/non availability of the node port."""
    incorrect_availablity = "not available" if available else "is available"
    assert (
        has_node_port(ops_test, node_port_name) == available
    ), f"Port information {incorrect_availablity} for service"


async def assert_all_unit_node_ports_available(ops_test: OpsTest):
    """Assert all ports available in mongos deployment."""
    for unit_id in range(len(ops_test.model.applications[MONGOS_APP_NAME].units)):
        assert_node_port_availablity(
            ops_test, node_port_name=f"{MONGOS_APP_NAME}-{unit_id}-external"
        )

        exposed_node_port = get_port_from_node_port(
            ops_test, node_port_name=f"{MONGOS_APP_NAME}-{unit_id}-external"
        )

        assert await is_external_mongos_client_reachable(
            ops_test, exposed_node_port
        ), "client is not reachable"


async def get_mongos_user_password(
    ops_test: OpsTest, app_name=MONGOS_APP_NAME, relation_name="cluster"
) -> tuple[str, str]:
    """Gets the username and password for the mongos client."""
    secret_uri = await get_application_relation_data(
        ops_test, app_name, relation_name=relation_name, key="secret-user"
    )
    assert secret_uri, "Failed to get the secret_uri."

    secret_data = await get_secret_data(ops_test, secret_uri)
    return secret_data.get("username"), secret_data.get("password")


async def is_external_mongos_client_reachable(ops_test: OpsTest, exposed_node_port: str) -> bool:
    """Returns True if the mongos client is reachable on the provided node port via the k8s ip."""
    public_k8s_ip = get_k8s_public_ip()
    username, password = await get_mongos_user_password(ops_test, MONGOS_APP_NAME)
    try:
        external_mongos_client = MongoClient(
            f"mongodb://{username}:{password}@{public_k8s_ip}:{exposed_node_port}"
        )
        external_mongos_client.admin.command("usersInfo")
    except ServerSelectionTimeoutError:
        return False
    finally:
        external_mongos_client.close()

    return True


async def assert_app_uri_matches_external_setting(
    ops_test: OpsTest, app_name: str, rel_name: str, external: bool
):
    """Assert that the APP uri that is built is correct.

    This means that it contains the correct host and port.
    """
    uri = await generate_mongos_uri(
        ops_test, "microk8s", auth=True, app_name=DATA_INTEGRATOR_APP_NAME, external=True
    )

    pulic_ip_present_in_uri = get_k8s_public_ip() in uri
    assert pulic_ip_present_in_uri == external, f"client URI for {app_name} has incorrect hosts."

    hostnames = await get_unit_hostnames(ops_test, "microk8s", MONGOS_APP_NAME)
    for host in hostnames:
        local_host_in_ip = host in uri
        assert local_host_in_ip != external, f"client URI for {app_name} has incorrect hosts."


async def assert_all_unit_node_ports_are_unavailable(ops_test: OpsTest):
    """Assert all ports available in mongos deployment."""
    for unit_id in range(len(ops_test.model.applications[MONGOS_APP_NAME].units)):
        assert_node_port_availablity(
            ops_test,
            node_port_name=f"{MONGOS_APP_NAME}-{unit_id}-external",
            available=False,
        )


async def get_sans_ips(ops_test: OpsTest, unit: JujuUnit, internal: bool) -> str:
    """Retrieves the sans for the for mongos on the provided unit."""
    cert_name = "internal" if internal else "external"
    get_sans_cmd = f"openssl x509 -noout -ext subjectAltName -in /etc/mongod/{cert_name}-cert.pem"
    complete_command = f"ssh --container mongos {unit.name} {get_sans_cmd}"
    _, result, _ = await ops_test.juju(*complete_command.split())
    return result
