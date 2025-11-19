# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import json
import os
from datetime import datetime
from logging import getLogger
from pathlib import Path
from typing import Literal

from juju.unit import Unit as JujuUnit
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, wait_exponential

from tests.integration.helpers.common import (
    MONGOD_PORT,
    MONGOS_APP_NAME,
    MONGOS_PORT,
    OPERATOR_USERNAME,
    ProcessError,
    get_address_of_unit,
    get_application_relation_data,
    get_password,
    get_secret_content,
    get_secret_id,
    mongosh,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)

TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"
TLS_RELATION_NAME = "certificates"

DIFFERENT_CERTIFICATES_APP_NAME = "self-signed-certificates-separate"

MONGODB_SNAP_CONF_DIR = "/var/snap/charmed-mongodb/current/etc/mongod"
MONGODB_ROCK_CONF_DIR = "/etc/mongod"

SNAP_MONGOD_SERVICE = "snap.charmed-mongodb.mongod.service"
SNAP_MONGOS_SERVICE = "snap.charmed-mongodb.mongos.service"


def external_cert_path(substrate: Substrate):
    if substrate == "lxd":
        return f"{MONGODB_SNAP_CONF_DIR}/external-ca.crt"
    return f"{MONGODB_ROCK_CONF_DIR}/external-ca.crt"


def external_pem_path(substrate: Substrate):
    if substrate == "lxd":
        return f"{MONGODB_SNAP_CONF_DIR}/external-cert.pem"
    return f"{MONGODB_ROCK_CONF_DIR}/external-cert.pem"


def internal_cert_path(substrate: Substrate):
    if substrate == "lxd":
        return f"{MONGODB_SNAP_CONF_DIR}/internal-ca.crt"
    return f"{MONGODB_ROCK_CONF_DIR}/internal-ca.crt"


async def mongo_tls_command(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    mongos: bool = False,
    uri: str | None = None,
) -> str:
    """Generates a command which verifies TLS status."""
    port = MONGOD_PORT if not mongos else MONGOS_PORT

    if not uri:
        replica_set_hosts = [
            await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
            for unit in ops_test.model.applications[app_name].units
        ]
        replica_set_hosts = [f"{host}:{port}" for host in replica_set_hosts]
        username = OPERATOR_USERNAME
        password = await get_password(ops_test, username, app_name=app_name)
        hosts = ",".join(replica_set_hosts)
        extra_args = f"?replicaSet={app_name}" if not mongos else ""
        uri = f"mongodb://{username}:{password}@{hosts}/admin{extra_args}"

    if app_name == MONGOS_APP_NAME:
        status_command = "db.getUsers()"
    else:
        status_command = "rs.status()" if not mongos else "sh.status()"

    return (
        f'{mongosh(substrate)} "{uri}"  --eval "{status_command}"'
        f" --tls --tlsCAFile {external_cert_path(substrate)}"
        f" --tlsCertificateKeyFile {external_pem_path(substrate)}"
    )


async def check_tls(
    ops_test: OpsTest,
    substrate: Substrate,
    unit: JujuUnit,
    enabled: bool,
    app_name: str,
    mongos: bool = False,
    container: str = "mongod",
    uri: str | None = None,
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
    try:
        for attempt in Retrying(
            stop=stop_after_attempt(10),
            wait=wait_exponential(multiplier=1, min=2, max=30),
        ):
            with attempt:
                ssh_command = (
                    ["ssh", "--container", container, unit.name]
                    if substrate == "microk8s"
                    else ["ssh", unit.name, "sudo"]
                )
                mongod_tls_check = await mongo_tls_command(
                    ops_test,
                    substrate=substrate,
                    app_name=app_name,
                    mongos=mongos,
                    uri=uri,
                )
                check_tls_cmd = ssh_command + [mongod_tls_check]
                return_code, stdout, stderr = await ops_test.juju(*check_tls_cmd)

                tls_enabled = return_code == 0
                if enabled != tls_enabled:
                    logger.warning("TLS disabled: STDOUT=%s STDERR=%s", stdout, stderr)
                    raise ValueError(
                        f"TLS is{' not' if not tls_enabled else ''} enabled on {unit.name}"
                    )
                return True
    except RetryError:
        return False


async def time_file_created(
    ops_test: OpsTest, substrate: Substrate, unit_name: str, path: str, container: str = "mongod"
) -> datetime:
    """Returns the unix timestamp of when a file was created on a specified unit."""
    if substrate == "lxd":
        time_cmd = f"ssh {unit_name} sudo ls -l --time-style=full-iso {path} "
    else:
        time_cmd = f"ssh --container {container} {unit_name} ls -l --time-style=full-iso {path} "
    return_code, ls_output, _ = await ops_test.juju(*time_cmd.split())

    if return_code != 0:
        raise ProcessError(
            "Expected time command %s to succeed instead it failed: %s",
            time_cmd,
            return_code,
        )

    return process_ls_time(ls_output)


def process_ls_time(ls_output):
    """Parse time representation as returned by the 'ls' command."""
    time_as_str = "T".join(ls_output.split("\n")[0].split(" ")[5:7])
    # further strip down additional milliseconds
    time_as_str = time_as_str[0:-3]
    return datetime.strptime(time_as_str, "%Y-%m-%dT%H:%M:%S.%f")


async def time_process_started(
    ops_test: OpsTest,
    substrate: Substrate,
    unit_name: str,
    process_name: str,
    container: str = "mongod",
) -> int:
    """Retrieves the time that a given process started according to systemd."""
    if substrate == "lxd":
        time_cmd = f"exec --unit {unit_name} --  systemctl show {process_name} --property=ActiveEnterTimestamp"
        return_code, systemctl_output, _ = await ops_test.juju(*time_cmd.split())

        if return_code != 0:
            raise ProcessError(
                "Expected time command %s to succeed instead it failed: %s",
                time_cmd,
                return_code,
            )
        return process_systemctl_time(systemctl_output)
    logs = await run_command_on_unit(
        ops_test, unit_name, "/charm/bin/pebble changes", container=container
    )

    # find most recent start time. By parsing most recent logs (ie in reverse order)
    for log in reversed(logs.split("\n")):
        if "Restart" in log:
            return process_pebble_time(log.split()[4])

    raise Exception("Service was never started")


async def run_command_on_unit(
    ops_test: OpsTest, unit_name: str, command: str, container: str = "mongod"
) -> str:
    """Run a command on a specific unit.

    Args:
        ops_test: The ops test framework instance
        unit_name: The name of the unit to run the command on
        command: The command to run

    Returns:
        the command output if it succeeds, otherwise raises an exception.
    """
    complete_command = f"ssh --container {container} {unit_name} {command}"
    return_code, stdout, stderr = await ops_test.juju(*complete_command.split())
    if return_code != 0:
        logger.warning(f"{complete_command} failed with {stdout=}, {stderr=}")
        raise Exception(
            "Expected command %s to succeed instead it failed: %s", command, return_code
        )
    return stdout


def process_pebble_time(changes_output):
    """Parse time representation as returned by the 'pebble changes' command."""
    return datetime.strptime(changes_output, "%H:%M")


def process_systemctl_time(systemctl_output) -> datetime:
    """Parse time representation as returned by the 'systemctl' command."""
    "ActiveEnterTimestamp=Thu 2022-09-22 10:00:00 UTC"
    time_as_str = "T".join(systemctl_output.split("=")[1].split(" ")[1:3])
    return datetime.strptime(time_as_str, "%Y-%m-%dT%H:%M:%S")


async def scp_file_preserve_ctime(
    ops_test: OpsTest, substrate: Substrate, unit_name: str, path: str, container: str = "mongod"
) -> str:
    """Returns the unix timestamp of when a file was created on a specified unit."""
    # Retrieving the file
    filename = path.split("/")[-1]
    if substrate == "lxd":
        complete_command = f"exec --unit {unit_name} -- sudo cat {path}"
        return_code, stdout, stderr = await ops_test.juju(*complete_command.split(), check=True)
        with open(filename, mode="w") as fd:
            fd.write(stdout.strip())
    else:
        complete_command = f"scp --container {container} {unit_name}:{path} {filename}"
        return_code, _, stderr = await ops_test.juju(*complete_command.split())

    if return_code != 0:
        logger.error(stderr)
        raise ProcessError(
            "Expected command %s to succeed instead it failed: %s; %s",
            complete_command,
            return_code,
            stderr,
        )

    return f"{filename}"


async def check_certs_correctly_distributed(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    unit: JujuUnit,
    container: str = "mongod",
) -> None:
    """Comparing expected vs distributed certificates.

    Verifying certificates downloaded on the charm against the ones distributed by the TLS operator
    """
    logger.info(f"Checking certs are correctly distributed for {unit}.")
    unit_secret_id = await get_secret_id(ops_test, unit.name)
    unit_secret_content = await get_secret_content(ops_test, unit_secret_id)

    # Get the values for certs from the relation, as provided by TLS Charm
    certificates_raw_data: str = await get_application_relation_data(
        ops_test, app_name, TLS_RELATION_NAME, "certificates"
    )
    certificates_data = json.loads(certificates_raw_data)

    # compare the TLS resources stored on the disk of the unit with the ones from the TLS relation
    for cert_type, cert_path in [
        ("int", internal_cert_path(substrate)),
        ("ext", external_cert_path(substrate)),
    ]:
        unit_csr = unit_secret_content[f"{cert_type}-csr-secret"]
        tls_item = [
            data
            for data in certificates_data
            if data["certificate_signing_request"].rstrip() == unit_csr.rstrip()
        ][0]

        # Read the content of the cert file stored in the unit
        cert_file_content = await get_file_content(
            ops_test, substrate, unit.name, cert_path, container=container
        )

        # Get the external cert value from the relation
        relation_cert = "\n".join(tls_item["chain"]).strip()

        # confirm that they match
        assert (
            relation_cert == cert_file_content
        ), f"Relation Content for {cert_type}-cert:\n{relation_cert}\nFile Content:\n{cert_file_content}\nMismatch."


async def set_private_key(ops_test: OpsTest, app_name: str, scope: Literal["peer", "client"]):
    """Sets the private key for one scope."""
    secret_name = f"tls-{scope}-private-key"

    data = Path(f"tests/integration/data/{scope}-key.pem").read_text()
    try:
        secret_id = await ops_test.model.add_secret(
            name=secret_name, data_args=[f"private-key={data}"]
        )
    except Exception:
        secrets = await ops_test.model.list_secrets({"label": secret_name})
        secret_id = secrets[0].uri
        await ops_test.model.update_secret(
            name=secret_name, data_args=[f"private-key={data}"], new_name=secret_name
        )

    await ops_test.model.grant_secret(secret_name=secret_name, application=app_name)

    logger.info(f"Setting the tls-{scope}-private-key config to {secret_id}")
    await ops_test.model.applications[app_name].set_config({f"tls-{scope}-private-key": secret_id})


async def get_file_content(
    ops_test: OpsTest,
    substrate: Substrate,
    unit_name: str,
    filepath: str,
    container: str = "mongod",
) -> str:
    # Read the content of the cert file stored in the unit
    cert_file_copy_path = await scp_file_preserve_ctime(
        ops_test, substrate, unit_name, filepath, container=container
    )
    with open(cert_file_copy_path) as f:
        cert_file_content = f.read()

    # cleanup the file
    os.remove(cert_file_copy_path)

    return cert_file_content


async def set_invalid_private_key(
    ops_test: OpsTest, app_name: str, scope: Literal["peer", "client"]
):
    """Sets the private key for one scope."""
    secret_name = f"tls-{scope}-private-key"

    try:
        secret_id = await ops_test.model.add_secret(
            name=secret_name, data_args=[f"private-key={base64.b64encode(b'invalid-key').decode()}"]
        )
    except Exception:
        secrets = await ops_test.model.list_secrets({"label": secret_name})
        secret_id = secrets[0].uri
        await ops_test.model.update_secret(
            name=secret_name,
            data_args=[f"private-key={base64.b64encode(b'invalid-key')}"],
            new_name=secret_name,
        )

    await ops_test.model.grant_secret(secret_name=secret_name, application=app_name)

    logger.info(f"Setting the tls-{scope}-private-key config to {secret_id}")
    await ops_test.model.applications[app_name].set_config({f"tls-{scope}-private-key": secret_id})


async def set_private_keys(ops_test: OpsTest, app_name: str) -> None:
    """Sets both private keys."""
    secrets = {}

    for scope in ("peer", "client"):
        secret_name = f"tls-{scope}-private-key"
        data = Path(f"tests/integration/data/{scope}-key.pem").read_text()

        try:
            secret_id = await ops_test.model.add_secret(
                name=secret_name, data_args=[f"private-key={data}"]
            )
        except Exception:
            _secrets = await ops_test.model.list_secrets({"label": secret_name})
            secret_id = _secrets[0].uri
            await ops_test.model.update_secret(
                name=secret_name, data_args=[f"private-key={data}"], new_name=secret_name
            )

        secrets[scope] = secret_id
        await ops_test.model.grant_secret(secret_name=secret_name, application=app_name)
        logger.info(f"Setting the tls-{scope}-private-key config to {secret_id}")

    await ops_test.model.applications[app_name].set_config(
        {f"tls-{scope}-private-key": secrets[scope] for scope in ("peer", "client")}
    )
