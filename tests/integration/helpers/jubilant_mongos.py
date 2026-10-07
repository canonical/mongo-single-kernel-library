#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import subprocess
import time
from logging import getLogger

import jubilant
from cryptography import x509
from jubilant.statustypes import UnitStatus
from kubernetes import client, config
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

from tests.integration.helpers.constants import (
    BASE,
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    DEPLOYMENT_TIMEOUT,
    MONGOS_APP_NAME,
    MONGOS_CLIENT_APPLICATION,
    MONGOS_CLUSTER_COMPONENTS,
    MONGOS_PORT,
    MONGOS_SOCKET,
    PING_CMD,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    SNAP_MONGOS_SERVICE,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
)
from tests.integration.helpers.continuous_writes_helpers import (
    clear_continuous_writes,
    start_continuous_writes,
    stop_continuous_writes,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    execute_on_mongod,
    external_cert_path,
    find_leader,
    get_application_relation_data,
    get_connection_string,
    get_file_content,
    get_ip_from_unit,
    get_mongodb_hostnames_for_app,
    get_relation_username_password,
    get_secret_by_uri,
    get_unit_id,
    internal_cert_path,
)
from tests.integration.helpers.jubilant_tls import (
    cannot_connect_without_tls,
    check_certs_correctly_distributed,
    check_tls,
    integrate_apps_with_tls,
    remove_tls_integrations,
    set_private_keys,
    time_file_created,
    time_process_started,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


def deploy_cluster_components(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    mongos_client_application_path: str,
    num_units_cluster_config: dict[str, int] | None = None,
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
        mongos_charm = "mongos" if substrate == Substrate.lxd else "mongos-k8s"

    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=config_server_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[config_server_name],
        config={"role": "config-server"},
    )
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=shard_one_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_one_name],
        config={"role": "shard"},
    )
    deploy_charm(
        juju,
        mongos_charm,
        substrate,
        app_name=MONGOS_APP_NAME,
        mongod_resource=mongos_resource,
        num_units=1 if substrate == Substrate.lxd else mongos_units,
        channel=channel,
    )

    juju.deploy(
        mongos_client_application_path,
        app=MONGOS_CLIENT_APPLICATION,
        num_units=mongos_units,
        base=BASE,
    )

    apps_to_wait_for = [config_server_name, shard_one_name, MONGOS_CLIENT_APPLICATION]

    if substrate == Substrate.k8s:
        apps_to_wait_for.append(MONGOS_APP_NAME)

    juju.wait(
        lambda status: are_agents_idle(status, *apps_to_wait_for, idle_period=20),
        timeout=DEPLOYMENT_TIMEOUT,
    )


def build_cluster(
    juju: jubilant.Juju,
    substrate: Substrate,
    integrate_with_mongos: bool = True,
    integrate_with_client: bool = True,
) -> None:
    """Connects the cluster components to each other."""
    if integrate_with_client:
        juju.integrate(MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME)
        juju.wait(
            lambda status: (
                are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
                and jubilant.all_blocked(status, MONGOS_APP_NAME)
            ),
            timeout=TIMEOUT,
        )

    # prepare sharded cluster
    juju.wait(
        lambda status: are_agents_idle(status, *MONGOS_CLUSTER_COMPONENTS, idle_period=20),
        timeout=TIMEOUT,
    )
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, *MONGOS_CLUSTER_COMPONENTS, idle_period=20
        )
    )

    apps = MONGOS_CLUSTER_COMPONENTS
    if integrate_with_mongos:
        # connect sharded cluster to mongos
        juju.integrate(
            f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
            f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
        )
        apps.append(MONGOS_APP_NAME)

    juju.wait(lambda status: are_apps_active_and_agents_idle(status, *apps, idle_period=20))


def generate_mongos_uri(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    auth: bool = True,
    external: bool = False,
    mongos_unit_status: UnitStatus | None = None,
) -> str:
    """Generates a URI for accessing mongos."""
    if mongos_unit_status is None:
        _, mongos_unit_status = find_leader(juju, app_name=app_name)

    if not external and substrate == Substrate.lxd:
        host = MONGOS_SOCKET
    else:
        host = f"{get_ip_from_unit(substrate, mongos_unit_status)}:{MONGOS_PORT}"

    if not auth:
        return f"mongodb://{host}"

    if substrate == Substrate.lxd:
        rel_name = "mongos"
    else:
        rel_name = "mongodb"

    secret_uri = get_application_relation_data(juju, app_name, rel_name, "secret-user")
    assert secret_uri, "No secret uri found."

    secret_data = get_secret_by_uri(juju, secret_uri)
    return secret_data.get("uris", "")


def is_mongos_running(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    unit_name: str,
    uri: str,
    tls: bool = False,
) -> bool:
    """Checks that mongos is running by executing the ping command."""
    output = execute_on_mongod(
        juju, substrate, app_name, uri, PING_CMD, tls, unit_name, container_name="mongos"
    )
    logger.info(
        "[mongos running check] ret_code: %s, stdout: %s, stderr: %s",
        output.return_code,
        output.stdout,
        output.stderr,
    )
    return output.return_code == 0


def get_k8s_public_ip() -> str:
    """Gets the public IP exposed by kubernetes.

    This is used when we're testing for external connection.
    """
    result = subprocess.run(
        "sudo k8s kubectl get nodes -o json", shell=True, capture_output=True, text=True
    )

    if result.returncode:
        logger.info("failed to retrieve public facing k8s IP error: %s", result.stderr)
        assert False, "failed to retrieve public facing k8s IP"

    node_info = json.loads(result.stdout)

    try:
        return node_info["items"][0]["status"]["addresses"][0]["address"]
    except KeyError:
        assert False, "failed to retrieve public facing k8s IP"


def get_sans_ips(juju: jubilant.Juju, unit: str, internal: bool) -> str:
    """Retrieves the sans for the for mongos on the provided unit."""
    cert_name = "internal" if internal else "external"
    get_sans_cmd = f"openssl x509 -noout -ext subjectAltName -in /etc/mongod/{cert_name}-cert.pem"
    return juju.ssh(unit, command=get_sans_cmd, container="mongos")


def get_node_port_info(model_name: str, node_port_name: str) -> int:
    """Gets the node port information.

    This is used when we're testing for external connection.
    """
    config.load_kube_config()
    v1 = client.CoreV1Api()

    namespaced_service = v1.read_namespaced_service(name=node_port_name, namespace=model_name)

    if not namespaced_service.spec:
        raise ValueError("Missing spec from namespace.")
    if not namespaced_service.spec.ports:
        raise ValueError("Missing port information from spec.")
    if not namespaced_service.spec.ports[0].node_port:
        raise ValueError("Missing NodePort information from port spec.")

    return namespaced_service.spec.ports[0].node_port


def get_external_uri(juju: jubilant.Juju, unit_name: str) -> str:
    """Builds the internal uri for mongos."""
    assert juju.model
    unit_id = get_unit_id(unit_name)
    exposed_node_port = get_node_port_info(
        model_name=juju.model, node_port_name=f"{MONGOS_APP_NAME}-{unit_id}-external"
    )
    public_k8s_ip = get_k8s_public_ip()
    username, password = get_relation_username_password(juju, MONGOS_APP_NAME, "cluster")
    return f"mongodb://{username}:{password}@{public_k8s_ip}:{exposed_node_port}"


def assert_mongos_tls_enabled(juju: jubilant.Juju, substrate: Substrate, internal: bool = True):
    # check mongos is running with TLS enabled
    for unit_name, unit_status in juju.status().get_units(MONGOS_APP_NAME).items():
        uri = (
            get_external_uri(juju, unit_name)
            if not internal
            else generate_mongos_uri(
                juju,
                substrate,
                auth=True,
                app_name=MONGOS_CLIENT_APPLICATION,
                external=not internal,
            )
        )
        assert check_tls(
            juju,
            substrate,
            unit_name,
            unit_status,
            app_name=MONGOS_APP_NAME,
            enabled=True,
            mongos=True,
            container="mongos",
            uri=uri,
        ), f"TLS not enabled on {unit_name}"
        assert cannot_connect_without_tls(
            juju,
            substrate,
            app_name=MONGOS_APP_NAME,
            unit_name=unit_name,
            unit_info=unit_status,
            mongos=True,
            container="mongos",
            uri=uri,
        ), f"Client can still connect without TLS on {unit_name}"
        assert check_continuous_writes(juju), "Client is not able to write to database."


def assert_mongos_tls_disabled(
    juju: jubilant.Juju, substrate: Substrate, internal: bool = True
) -> None:
    # check mongos is running with TLS enabled
    for unit_name, unit_status in juju.status().get_units(MONGOS_APP_NAME).items():
        uri = (
            get_external_uri(juju, unit_name)
            if not internal
            else generate_mongos_uri(
                juju,
                substrate,
                auth=True,
                app_name=MONGOS_CLIENT_APPLICATION,
                external=not internal,
            )
        )
        assert check_tls(
            juju,
            substrate,
            unit_name,
            unit_status,
            app_name=MONGOS_APP_NAME,
            enabled=False,
            mongos=True,
            container="mongos",
            uri=uri,
        ), f"TLS not enabled on {unit_name}"


def rotate_and_verify_certs(juju: jubilant.Juju, substrate: Substrate, app_name: str) -> None:
    """Verify provided app can rotate its TLS certs."""
    original_tls_info = {}

    ext_cert_path = external_cert_path(substrate)
    int_cert_path = internal_cert_path(substrate)

    for unit_name in juju.status().get_units(app_name).keys():
        original_tls_info[unit_name] = {}
        original_tls_info[unit_name]["external_cert_contents"] = get_file_content(
            juju, substrate, unit_name, ext_cert_path, container="mongos"
        )
        original_tls_info[unit_name]["internal_cert_contents"] = get_file_content(
            juju, substrate, unit_name, int_cert_path, container="mongos"
        )
        original_tls_info[unit_name]["external_cert"] = time_file_created(
            juju, substrate, unit_name, ext_cert_path, container="mongos"
        )
        original_tls_info[unit_name]["internal_cert"] = time_file_created(
            juju, substrate, unit_name, int_cert_path, container="mongos"
        )
        original_tls_info[unit_name]["mongos_service"] = time_process_started(
            juju, substrate, unit_name, SNAP_MONGOS_SERVICE, container="mongos"
        )
        check_certs_correctly_distributed(
            juju, substrate, app_name=app_name, unit_name=unit_name, container="mongos"
        )

    set_private_keys(juju, app_name)

    # wait for certificate to be available and processed. Can get receive two certificate
    # available events and restart twice so we want to ensure we are idle for at least 1 minute
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=60,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    # After updating both the external key and the internal key a new certificate request will be
    # made; then the certificates should be available and updated.
    for unit_name in juju.status().get_units(app_name).keys():
        new_external_cert = get_file_content(
            juju, substrate, unit_name, ext_cert_path, container="mongos"
        )
        new_internal_cert = get_file_content(
            juju, substrate, unit_name, int_cert_path, container="mongos"
        )
        new_external_cert_time = time_file_created(
            juju, substrate, unit_name, ext_cert_path, container="mongos"
        )
        new_internal_cert_time = time_file_created(
            juju, substrate, unit_name, int_cert_path, container="mongos"
        )
        new_mongos_service_time = time_process_started(
            juju, substrate, unit_name, SNAP_MONGOS_SERVICE, container="mongos"
        )

        check_certs_correctly_distributed(
            juju, substrate, app_name=app_name, unit_name=unit_name, container="mongos"
        )
        assert (
            new_external_cert != original_tls_info[unit_name]["external_cert_contents"]
        ), f"external cert for {unit_name} not rotated."

        assert (
            new_internal_cert != original_tls_info[unit_name]["internal_cert_contents"]
        ), f"internal cert for {unit_name} not rotated."

        assert (
            new_external_cert_time > original_tls_info[unit_name]["external_cert"]
        ), f"external cert for {unit_name} was not updated."
        assert (
            new_internal_cert_time > original_tls_info[unit_name]["internal_cert"]
        ), f"internal cert for {unit_name} was not updated."

        # Once the certificate requests are processed and updated the .service file should be
        # restarted
        assert (
            new_mongos_service_time > original_tls_info[unit_name]["mongos_service"]
        ), f"mongos service for {unit_name} was not restarted."

    # Verify that TLS is functioning on all units.
    assert_mongos_tls_enabled(juju, substrate)


def toggle_tls_mongos(
    juju: jubilant.Juju, enable: bool, certs_app_name: str = TLS_CERTIFICATES_APP_NAME
) -> None:
    """Toggles TLS on mongos application to the specified enabled state."""
    if enable:
        integrate_apps_with_tls(juju, MONGOS_APP_NAME, cert_provider_app=certs_app_name)
    else:
        remove_tls_integrations(juju, MONGOS_APP_NAME, cert_provider_app=certs_app_name)


def check_continuous_writes(juju: jubilant.Juju):
    """Checks that continuous writes are working as expected."""
    secret_tls = None
    for relation_data in juju.show_unit(f"{MONGOS_CLIENT_APPLICATION}/0").relation_info:
        if relation_data.endpoint == "mongos" and relation_data.related_endpoint == "mongos_proxy":
            secret_tls = relation_data.app_data.get("secret-tls")

    assert secret_tls, "Missing secret-tls in relation databag."
    secret = get_secret_by_uri(juju, secret_tls)
    assert secret.get("tls") == "True"

    tls_certificate = secret.get("tls-ca")
    assert tls_certificate, "No TLS CA in secret."

    parsed_cert = x509.load_pem_x509_certificate(data=tls_certificate.encode())
    _common_name = parsed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    common_name = str(_common_name[0].value) if _common_name else ""

    assert common_name == "Test CA"

    start_continuous_writes(juju, MONGOS_CLIENT_APPLICATION)
    time.sleep(20)
    n_writes = stop_continuous_writes(juju, MONGOS_CLIENT_APPLICATION)
    clear_continuous_writes(juju, MONGOS_CLIENT_APPLICATION)

    return n_writes != -1


def has_node_port(model: str, node_port_name: str) -> bool:
    """Checks if the node has a node port enabled."""
    try:
        get_node_port_info(model, node_port_name)
    except ValueError:
        return False
    return True


def assert_node_port_availablity(model: str, node_port_name: str, available: bool = True) -> None:
    """Checks the availability/non availability of the node port."""
    incorrect_availablity = "not available" if available else "is available"
    assert (
        has_node_port(model, node_port_name) == available
    ), f"Port information {incorrect_availablity} for service"


def assert_all_unit_node_ports_available(juju: jubilant.Juju):
    """Assert all ports available in mongos deployment."""
    assert juju.model
    for unit_name in juju.status().get_units(MONGOS_APP_NAME):
        unit_id = get_unit_id(unit_name)
        assert_node_port_availablity(
            juju.model, node_port_name=f"{MONGOS_APP_NAME}-{unit_id}-external"
        )

        exposed_node_port = get_node_port_info(
            juju.model, node_port_name=f"{MONGOS_APP_NAME}-{unit_id}-external"
        )

        assert is_external_mongos_client_reachable(
            juju, exposed_node_port
        ), "client is not reachable"


def assert_all_unit_node_ports_are_unavailable(juju: jubilant.Juju):
    """Assert all ports available in mongos deployment."""
    assert juju.model
    for unit_name in juju.status().get_units(MONGOS_APP_NAME):
        unit_id = get_unit_id(unit_name)
        assert_node_port_availablity(
            juju.model,
            node_port_name=f"{MONGOS_APP_NAME}-{unit_id}-external",
            available=False,
        )


def assert_app_uri_matches_external_setting(
    juju: jubilant.Juju, app_name: str, rel_name: str, external: bool
):
    """Assert that the APP uri that is built is correct.

    This means that it contains the correct host and port.
    """
    uri = get_connection_string(juju, app_name, rel_name)

    pulic_ip_present_in_uri = get_k8s_public_ip() in uri
    assert pulic_ip_present_in_uri == external, f"client URI for {app_name} has incorrect hosts."

    hostnames = get_mongodb_hostnames_for_app(juju, Substrate.k8s, MONGOS_APP_NAME)
    for host in hostnames:
        local_host_in_ip = host in uri
        assert local_host_in_ip != external, f"client URI for {app_name} has incorrect hosts."


def is_external_mongos_client_reachable(juju: jubilant.Juju, exposed_node_port: str) -> bool:
    """Returns True if the mongos client is reachable on the provided node port via the k8s ip."""
    public_k8s_ip = get_k8s_public_ip()
    username, password = get_relation_username_password(juju, MONGOS_APP_NAME, CLUSTER_REL_NAME)
    if not username or not password:
        return False

    with MongoClient(
        f"mongodb://{username}:{password}@{public_k8s_ip}:{exposed_node_port}"
    ) as external_mongos_client:
        try:
            external_mongos_client.admin.command("usersInfo")
        except ServerSelectionTimeoutError:
            return False
    return True
