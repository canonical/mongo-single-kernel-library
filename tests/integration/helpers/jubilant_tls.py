#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import json
from datetime import datetime
from logging import getLogger
from pathlib import Path
from typing import Literal

import jubilant
from jubilant.statustypes import UnitStatus
from tenacity import RetryError, Retrying, stop_after_attempt, wait_exponential

from tests.integration.helpers.common import ProcessError
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    CLIENT_TLS_RELATION_NAME,
    MONGOS_APP_NAME,
    PEER_TLS_RELATION_NAME,
    TLS_CERTIFICATES_APP_NAME,
)
from tests.integration.helpers.jubilant_common import (
    execute_on_mongod,
    external_cert_path,
    get_application_relation_data,
    get_file_content,
    get_ip_from_unit,
    get_password,
    get_secret_by_uri,
    get_secret_uri_by_owner,
    get_unit_id,
    internal_cert_path,
    run_command_on_server,
    unit_uri,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


def integrate_apps_with_tls(
    juju: jubilant.Juju,
    *apps: str,
    cert_provider_app: str = TLS_CERTIFICATES_APP_NAME,
    peer: bool = True,
    client: bool = True,
) -> None:
    """Integrates a list of applications with self-signed certs operator."""
    for app in apps:
        if peer:
            juju.integrate(
                f"{cert_provider_app}",
                f"{app}:{PEER_TLS_RELATION_NAME}",
            )
        if client:
            juju.integrate(
                f"{cert_provider_app}",
                f"{app}:{CLIENT_TLS_RELATION_NAME}",
            )


def remove_tls_integrations(
    juju: jubilant.Juju,
    *apps: str,
    cert_provider_app: str = TLS_CERTIFICATES_APP_NAME,
    peer: bool = True,
    client: bool = True,
) -> None:
    """Removes the TLS integration from a list of applications."""
    for app in apps:
        if peer:
            juju.remove_relation(
                f"{app}:{PEER_TLS_RELATION_NAME}",
                f"{cert_provider_app}",
            )
        if client:
            juju.remove_relation(
                f"{app}:{CLIENT_TLS_RELATION_NAME}",
                f"{cert_provider_app}",
            )


def check_tls(
    juju: jubilant.Juju,
    substrate: Substrate,
    unit_name: str,
    unit_info: UnitStatus,
    enabled: bool,
    app_name: str,
    mongos: bool = False,
    container: str = "mongod",
) -> bool:
    """Returns whether TLS is enabled on the specific MongoDB instance.

    Args:
        ops_test: The ops test framework instance.
        unit: The unit to be checked.
        enabled: check if TLS is enabled/disabled
        app_name: name of running mongodb app
        mongos: whether sharded deployment of replica set

    Returns:
        Whether TLS is enabled/disabled.
    """
    assert juju.model
    if app_name == MONGOS_APP_NAME:
        status_command = "db.version()"
    elif mongos:
        status_command = "sh.status()"
    else:
        status_command = "rs.status()"

    username = CHARMED_OPERATOR_USERNAME
    password = get_password(juju, app_name=app_name, username=username)
    host = get_ip_from_unit(substrate=substrate, unit_info=unit_info)
    if substrate == "microk8s":
        unit_id = get_unit_id(unit_name)
        model_name = juju.model
        host = f"mongodb-k8s-{unit_id}.mongodb-k8s-endpoints.{model_name}.svc.cluster.local"

    uri = unit_uri(username, password, ip_address=host, mongos=mongos)

    try:
        for attempt in Retrying(
            stop=stop_after_attempt(10),
            wait=wait_exponential(multiplier=1, min=2, max=30),
        ):
            with attempt:
                output = execute_on_mongod(
                    juju,
                    substrate,
                    unit_name=unit_name,
                    app_name=app_name,
                    uri=uri,
                    command=status_command,
                    tls=enabled,
                    container_name=container,
                )

                tls_enabled = output.return_code == 0
                if enabled != tls_enabled:
                    logger.warning(
                        "TLS is%s enabled: STDOUT=%s STDERR=%s",
                        " not" if not tls_enabled else "",
                        output.stdout,
                        output.stderr,
                    )
                    raise ValueError(
                        f"TLS is{' not' if not tls_enabled else ''} enabled on {unit_name}"
                    )
                return True
    except RetryError:
        return False
    return False


def cannot_connect_without_tls(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    unit_name: str,
    unit_info: UnitStatus,
    mongos: bool = False,
    container: str = "mongod",
):
    """Confirms that we cannot connect without TLS.

    Args:
        ops_test: The ops test framework instance.
        unit: The unit to be checked.
        enabled: check if TLS is enabled/disabled
        app_name: name of running mongodb app
        mongos: whether sharded deployment of replica set

    Returns:
        True if we can't connect without TLS
    """
    if app_name == MONGOS_APP_NAME:
        status_command = "db.version()"
    elif mongos:
        status_command = "sh.status()"
    else:
        status_command = "rs.status()"

    username = CHARMED_OPERATOR_USERNAME
    password = get_password(juju, app_name=app_name, username=username)
    host = get_ip_from_unit(substrate=substrate, unit_info=unit_info)
    if substrate == "microk8s":
        unit_id = get_unit_id(unit_name)
        model_name = juju.model
        host = f"mongodb-k8s-{unit_id}.mongodb-k8s-endpoints.{model_name}.svc.cluster.local"

    uri = unit_uri(username, password, ip_address=host, mongos=mongos)
    output = execute_on_mongod(
        juju,
        substrate,
        unit_name=unit_name,
        app_name=app_name,
        uri=uri,
        command=status_command,
        tls=False,
        container_name=container,
    )

    tls_disabled = output.return_code == 1
    if not tls_disabled:
        logger.warning("Can connect with TLS on %s", unit_name)
        return False
    return True


def time_file_created(
    juju: jubilant.Juju, substrate: Substrate, unit_name: str, path: str, container: str = "mongod"
) -> datetime:
    """Returns the unix timestamp of when a file was created on a specified unit."""
    try:
        output = run_command_on_server(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            command=f"ls -l --time-style=full-iso {path}",
            container=container,
        )
        return process_ls_time(output)
    except jubilant.CLIError as e:
        raise ProcessError(
            "Expected time command %s to succeed instead it failed: %s",
            e.cmd,
            e.returncode,
        )


def process_ls_time(ls_output):
    """Parse time representation as returned by the 'ls' command."""
    time_as_str = "T".join(ls_output.split("\n")[0].split(" ")[5:7])
    # further strip down additional milliseconds
    time_as_str = time_as_str[0:-3]
    return datetime.strptime(time_as_str, "%Y-%m-%dT%H:%M:%S.%f")


def process_pebble_time(changes_output: str) -> datetime:
    """Parse time representation as returned by the 'pebble changes' command."""
    return datetime.strptime(changes_output, "%H:%M")


def process_systemctl_time(systemctl_output: str) -> datetime:
    """Parse time representation as returned by the 'systemctl' command."""
    "ActiveEnterTimestamp=Thu 2022-09-22 10:00:00 UTC"
    time_as_str = "T".join(systemctl_output.split("=")[1].split(" ")[1:3])
    return datetime.strptime(time_as_str, "%Y-%m-%dT%H:%M:%S")


def time_process_started(
    juju: jubilant.Juju,
    substrate: Substrate,
    unit_name: str,
    process_name: str,
    container: str = "mongod",
) -> datetime:
    """Retrieves the time that a given process started according to systemd."""
    if substrate == "lxd":
        systemctl_output = run_command_on_server(
            juju,
            substrate=substrate,
            unit_name=unit_name,
            command=f"systemctl show {process_name} --property=ActiveEnterTimestamp",
        )
        return process_systemctl_time(systemctl_output)

    logs = run_command_on_server(
        juju,
        substrate=substrate,
        unit_name=unit_name,
        command="/charm/bin/pebble changes",
        container=container,
    )

    # find most recent start time. By parsing most recent logs (ie in reverse order)
    for log in reversed(logs.split("\n")):
        if "Restart" in log:
            return process_pebble_time(log.split()[4])

    raise Exception("Service was never started")


def check_certs_correctly_distributed(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    unit_name: str,
    container: str = "mongod",
) -> None:
    """Comparing expected vs distributed certificates.

    Verifying certificates downloaded on the charm against the ones distributed by the TLS operator
    """
    unit_secret_uri = get_secret_uri_by_owner(juju, app_or_unit=unit_name, label=f"{app_name}.unit")

    unit_secret_content = get_secret_by_uri(juju, uri=unit_secret_uri)

    # Get the values for certs from the relation, as provided by TLS Charm
    peer_certificates_raw_data = get_application_relation_data(
        juju, app_name, PEER_TLS_RELATION_NAME, "certificates"
    )
    assert peer_certificates_raw_data, "Missing certificate in peer TLS relation."
    peer_certificates_data = json.loads(peer_certificates_raw_data)

    client_certificates_raw_data = get_application_relation_data(
        juju, app_name, CLIENT_TLS_RELATION_NAME, "certificates"
    )
    assert client_certificates_raw_data, "Missing certificate in client TLS relation."
    client_certificates_data = json.loads(client_certificates_raw_data)

    # compare the TLS resources stored on the disk of the unit with the ones from the TLS relation
    for cert_type, cert_path, certificates_data in [
        ("int", internal_cert_path(substrate), peer_certificates_data),
        ("ext", external_cert_path(substrate), client_certificates_data),
    ]:
        unit_csr = unit_secret_content[f"{cert_type}-csr-secret"]
        tls_item = [
            data
            for data in certificates_data
            if data["certificate_signing_request"].rstrip() == unit_csr.rstrip()
        ][0]

        # Read the content of the cert file stored in the unit
        cert_file_content = get_file_content(
            juju, substrate, unit_name, cert_path, container=container
        )

        # Get the external cert value from the relation
        relation_cert = "\n".join(tls_item["chain"]).strip()

        # confirm that they match
        assert (
            relation_cert == cert_file_content
        ), f"Relation Content for {cert_type}-cert:\n{relation_cert}\nFile Content:\n{cert_file_content}\nMismatch."


def set_private_keys(juju: jubilant.Juju, app_name: str) -> None:
    """Sets both private keys."""
    secrets = {}

    for scope in ("peer", "client"):
        secret_name = f"tls-{scope}-private-key"
        data = Path(f"tests/integration/data/{scope}-key.pem").read_text()

        try:
            secret_id = juju.add_secret(name=secret_name, content={"private-key": data})
        except jubilant.CLIError:
            _secrets = juju.show_secret(identifier=secret_name)
            secret_id = _secrets.uri
            juju.update_secret(
                identifier=secret_id, content={"private-key": data}, name=secret_name
            )

        secrets[scope] = secret_id
        juju.grant_secret(identifier=secret_name, app=app_name)
        logger.info(f"Setting the tls-{scope}-private-key config to {secret_id}")

    juju.config(
        app_name, {f"tls-{scope}-private-key": secrets[scope] for scope in ("peer", "client")}
    )


def set_private_key(juju: jubilant.Juju, app_name: str, scope: Literal["peer", "client"]):
    """Sets the private key for one scope."""
    secret_name = f"tls-{scope}-private-key"
    data = Path(f"tests/integration/data/{scope}-key.pem").read_text()

    try:
        secret_id = juju.add_secret(
            name=secret_name,
            content={"private-key": data},
        )
    except Exception:
        _secrets = juju.show_secret(identifier=secret_name)
        secret_id = _secrets.uri
        juju.update_secret(
            identifier=secret_id,
            content={"private-key": data},
            name=secret_name,
        )

    juju.grant_secret(identifier=secret_name, app=app_name)

    logger.info(f"Setting the tls-{scope}-private-key config to {secret_id}")
    juju.config(app_name, {f"tls-{scope}-private-key": secret_id})


def set_invalid_private_key(juju: jubilant.Juju, app_name: str, scope: Literal["peer", "client"]):
    """Sets the private key for one scope."""
    secret_name = f"tls-{scope}-private-key"

    try:
        secret_id = juju.add_secret(
            name=secret_name,
            content={"private-key": f"{base64.b64encode(b'invalid-key').decode()}"},
        )
    except Exception:
        _secrets = juju.show_secret(identifier=secret_name)
        secret_id = _secrets.uri
        juju.update_secret(
            identifier=secret_id,
            content={"private-key": f"{base64.b64encode(b'invalid-key').decode()}"},
            name=secret_name,
        )

    juju.grant_secret(identifier=secret_name, app=app_name)

    logger.info(f"Setting the tls-{scope}-private-key config to {secret_id}")
    juju.config(app_name, {f"tls-{scope}-private-key": secret_id})
