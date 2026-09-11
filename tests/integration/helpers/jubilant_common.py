#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import math
from datetime import datetime
from typing import NamedTuple

import jubilant
from bson.json_util import dumps as bson_dumps
from jubilant._juju import ConstraintValue
from jubilant.statustypes import UnitStatus
from pymongo import MongoClient
from tenacity import (
    retry,
    retry_if_result,
    stop_after_attempt,
    wait_exponential,
)

from tests.integration.helpers.common import (
    CHARMED_OPERATOR_USERNAME,
    DEFAULT_DATABASE_NAME,
    INTERNAL_USER_PASSWORD_CONFIG,
    MONGOD_PORT,
    MONGOS_PORT,
    TEST_DOCUMENTS,
    CommandResult,
    ProcessError,
    SecretNotFoundError,
    external_cert_path,
    find_json,
    mongosh,
)
from tests.integration.helpers.constants import BASE, TIMEOUT
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


def existing_app(
    juju: jubilant.Juju, charm_name: str = "mongodb", test_deployments: list[str] | None = None
) -> str | None:
    """Return the name of an existing mongodb application.

    Args:
        juju: the Jubilant juju object.
        charm_name: the charm name we're looking for
        test_deployments: Some known deployments the function should not consider when looking for
            the application.

    Returns:
        str | None: name of an application deployment for `charm_name` if it exists, None otherwise.
    """
    test_deployments = test_deployments or []
    for app_name, app_status in juju.status().apps.items():
        if charm_name in app_status.charm_name:
            if app_name in test_deployments:
                logger.debug(
                    "%s app name '%s' was deployed by the tests, not by the user",
                    charm_name,
                    app_name,
                )
                continue
            return app_name

    return None


def deploy_charm(
    juju: jubilant.Juju,
    charm: str,
    substrate: Substrate,
    app_name: str,
    num_units: int = 3,
    mongod_resource: dict[str, str] | None = None,
    channel: str | None = None,
    revision: int | None = None,
    config: dict[str, str] | None = None,
    subordinate: bool = False,
    storage: dict[str, str] | None = None,
    base: str | None = None,
    constraints: dict[str, ConstraintValue] | None = None,
    bind: dict[str, str] | None = None,
):
    if revision is not None:
        channel = "8/beta"
    if substrate == "microk8s":
        base = base or BASE
        juju.deploy(
            charm,
            app=app_name,
            revision=revision,
            resources=(mongod_resource if not channel else None),
            num_units=0 if subordinate else num_units,
            base=base,
            trust=True,
            config=config,
            channel=channel,
            storage=storage,
        )
    else:
        juju.deploy(
            charm,
            app=app_name,
            num_units=0 if subordinate else num_units,
            revision=revision,
            config=config,
            channel=channel,
            storage=storage,
            constraints=constraints,
            bind=bind,
        )


def remove_number_units(
    juju: jubilant.Juju, substrate: Substrate, app_name: str, num_units: int
) -> None:
    """Remove a specified number of units from an application.

    Args:
        juju: An instance of Jubilant's Juju class on which to run Juju commands
        app: The name of the application from which to remove units
        num_units: The number of units to remove
        substrate: The substrate type ("k8s" or "vm")
    """
    match substrate:
        case "microk8s":
            juju.remove_unit(app_name, num_units=num_units)
        case "lxd":
            # get units names
            unit_names = list(juju.status().get_units(app_name))
            # remove units by name until num_units have been removed
            juju.remove_unit(*unit_names[:num_units])


def ensure_app_number_units(
    juju: jubilant.Juju, substrate: Substrate, app_name: str, required_units: int
) -> None:
    """A helper function that scales existing cluster if necessary."""
    # check if we need to scale
    current_units = len(juju.status().get_units(app_name))

    if current_units == required_units:
        return

    if current_units > required_units:
        units_to_remove = current_units - required_units
        remove_number_units(
            juju=juju, substrate=substrate, app_name=app_name, num_units=units_to_remove
        )
    else:
        units_to_add = required_units - current_units
        juju.add_unit(app_name, num_units=units_to_add)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=10, unit_count=required_units
        ),
        timeout=TIMEOUT,
    )


def find_leader(juju: jubilant.Juju, app_name: str) -> tuple[str, UnitStatus]:
    units = juju.status().get_units(app_name)
    return next((name, unit) for name, unit in units.items() if unit.leader)


def get_secret_by_label(juju: jubilant.Juju, label: str) -> dict[str, str]:
    for secret in juju.secrets():
        if label == secret.label:
            revealed_secret = juju.show_secret(secret.uri, reveal=True)
            return revealed_secret.content

    raise SecretNotFoundError(f"Secret with label {label} not found")


def get_password(juju: jubilant.Juju, app_name: str, username: str):
    secret = get_secret_by_label(juju, f"{app_name}.app")
    return secret[f"{username}-password"]


def get_ip_from_unit(substrate: Substrate, unit_info: UnitStatus) -> str:
    """Get the IP address of a unit based on the substrate type."""
    return unit_info.public_address if substrate == "lxd" else unit_info.address


def run_command_on_server(
    juju: jubilant.Juju,
    substrate: Substrate,
    unit_name: str,
    command: str,
    container: str = "mongod",
) -> str:
    """Executes a command on the workload machine."""
    effective_container = container if substrate == "microk8s" else None
    if substrate == "lxd":
        command = f"sudo {command}"

    return juju.ssh(unit_name, command, container=effective_container)


def unit_has_file(
    juju: jubilant.Juju,
    substrate: Substrate,
    unit_name: str,
    dir_path: str,
    filename: str,
    container: str = "mongod",
) -> bool:
    files = run_command_on_server(juju, substrate, unit_name, f"ls {dir_path}", container=container)
    return filename in files


def _uri(
    username: str,
    password: str,
    hosts: list[str],
    replica_set: str | None = None,
    mongos: bool = False,
) -> str:
    port = MONGOS_PORT if mongos else MONGOD_PORT
    _hosts = ",".join(f"{host}:{port}" for host in hosts)
    if mongos:
        return f"mongodb://{username}:{password}@{_hosts}/admin"
    if replica_set:
        return f"mongodb://{username}:{password}@{hosts}:{_hosts}/admin?replicaSet={replica_set}"
    return f"mongodb://{username}:{password}@{hosts}:{_hosts}/admin"


def unit_uri(
    username: str,
    password: str,
    ip_address: str,
    replica_set: str | None = None,
    mongos: bool = False,
) -> str:
    """Generates URI that is used by MongoDB to connect to a single replica.

    Args:
        username: the username we're trying to connect with
        password: password of database.
        ip_address: ip address of replica/unit
        replica_set: name of application which has the cluster.
        mongos: If true, we connect to mongos, hence use port 27108. Ignores replica_set parameter
    """
    return _uri(username, password, [ip_address], replica_set, mongos)


def replica_set_uri(
    username: str,
    password: str,
    ip_addresses: list[str],
    replica_set: str,
) -> str:
    """Generates URI that is used by MongoDB to connect to a replica set.

    Args:
        username: the username we're trying to connect with
        password: password of database.
        ip_addresses: list of ip addresses of the units
        replica_set: name of application which has the cluster.
    """
    return _uri(username, password, ip_addresses, replica_set, mongos=False)


def mongos_uri(
    username: str,
    password: str,
    ip_addresses: list[str],
):
    """Generates URI that is used by MongoDB to connect to some mongos instances.

    Args:
        username: the username we're trying to connect with
        password: password of database.
        ip_addresses: list of ip addresses of the units
    """
    return _uri(username, password, ip_addresses, replica_set=None, mongos=True)


@retry(
    retry=retry_if_result(lambda x: x == 0),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=30),
)
def count_primaries(juju: jubilant.Juju, substrate: Substrate, app_name: str) -> int:
    """Counts the number of primaries in a replica set.

    Will retry counting when the number of primaries is 0 at most 5 times.
    """
    number_of_primaries = 0

    password = get_password(
        juju=juju,
        app_name=app_name,
        username=CHARMED_OPERATOR_USERNAME,
    )
    for unit_info in juju.status().get_units(app_name).values():
        # get unit
        ip_address = get_ip_from_unit(substrate=substrate, unit_info=unit_info)

        # connect to mongod
        uri = unit_uri(
            username=CHARMED_OPERATOR_USERNAME,
            password=password,
            ip_address=ip_address,
            replica_set=app_name,
        )
        client = MongoClient(uri, directConnection=True)

        # check primary status
        if client.is_primary:
            number_of_primaries += 1

    return number_of_primaries


def set_password(
    juju: jubilant.Juju,
    app_name: str,
    username: str,
    password: str,
) -> None:
    """Set a user password (or update it if existing) via secret.

    Args:
        juju: An instance of Jubilant's Juju class on which to run Juju commands
        app_name: the application the created secret will be granted to
        username: the user to set the password for
        password: the password to use
    """
    secret_name = "system_users_secret"

    # if secret exists, update it, else add secret
    existing = next((s for s in juju.secrets() if s.name == secret_name), None)
    if existing:
        juju.update_secret(identifier=existing.uri, content={username: password})
        secret_id = existing.uri
    else:
        secret_id = juju.add_secret(name=secret_name, content={username: password})

    # grant the application access to this secret
    juju.grant_secret(identifier=secret_id, app=app_name)

    # update the application config to include the secret
    juju.config(app=app_name, values={INTERNAL_USER_PASSWORD_CONFIG: secret_id})
    logger.info(
        f"Setting the {INTERNAL_USER_PASSWORD_CONFIG} config in {app_name} to {secret_id} {username}={password}"
    )


def execute_on_mongod(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    uri: str,
    command: str,
    tls: bool = False,
    stringify: bool = True,
    expecting_output: bool = True,
    container_name: str = "mongod",
):
    """Executes the command with mongosh on the host."""
    tls_string = ""
    if tls:
        tls_string = f"--tls --tlsCAFile {external_cert_path(substrate)}"

    if stringify:
        formatted_string = f'"{uri}" --quiet --eval "EJSON.stringify({command})" {tls_string}'
    else:
        formatted_string = f'"{uri}" --quiet --eval "{command}" {tls_string}'

    unit_name = f"{app_name}/leader"
    cmd = [mongosh(substrate), formatted_string]

    try:
        stdout = juju.ssh(unit_name, *cmd, container=container_name)
        ret_code = 0
        stderr = ""
    except jubilant.CLIError as e:
        logger.error("Failed to execute command '%s': %s, %s", command, e.stderr, e.stdout)
        stdout = e.stdout
        stderr = e.stderr
        ret_code = e.returncode

    data = None
    if expecting_output:
        try:
            data = find_json(stdout)
        except json.JSONDecodeError:
            pass

    return CommandResult(
        return_code=ret_code,
        stdout=stdout,
        stderr=stderr,
        data=data,
    )


def is_relation_joined(
    status: jubilant.Status,
    app_one: str,
    app_two: str,
    endpoint_one: str,
    endpoint_two: str,
) -> bool:
    """Checks if the relation is joined for the two applications on the right endpoints."""
    if app_one not in status.apps:
        return False
    if app_two not in status.apps:
        return False

    rels = {app_one: False, app_two: False}
    for app, endpoint, remote_app in (
        (app_one, endpoint_one, app_two),
        (app_two, endpoint_two, app_one),
    ):
        for rel_name, relations in status.apps[app].relations.items():
            if rel_name != endpoint:
                continue
            for rel in relations:
                if rel.related_app == remote_app:
                    rels[app] = True
                    break
    return rels[app_one] and rels[app_two]


def deploy_application(
    juju: jubilant.Juju,
    application_path: str,
    app_name: str,
    database_name: str = DEFAULT_DATABASE_NAME,
    constraints: dict[str, ConstraintValue] | None = None,
    bind: dict[str, str] | None = None,
):
    """Deploy the helpers applications with one unit and waits for idle."""
    application_name = existing_app(juju, charm_name=app_name)
    if application_name:
        return

    juju.deploy(
        charm=application_path,
        app=app_name,
        num_units=1,
        base=BASE,
        constraints=constraints,
        config={"database-name": database_name},
        bind=bind,
    )
    juju.wait(
        lambda status: are_agents_idle(status, app_name, idle_period=30, unit_count=1),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


def relate_application(juju: jubilant.Juju, mongodb_application_name: str, client_app_name: str):
    if is_relation_joined(
        juju.status(),
        app_one=mongodb_application_name,
        app_two=client_app_name,
        endpoint_one="database",
        endpoint_two="mongodb",
    ):
        return

    juju.integrate(f"{mongodb_application_name}:database", f"{client_app_name}:mongodb")

    juju.wait(
        lambda status: is_relation_joined(
            status,
            app_one=mongodb_application_name,
            app_two=client_app_name,
            endpoint_one="database",
            endpoint_two="mongodb",
        )
    )
    juju.wait(
        lambda status: are_agents_idle(
            status, mongodb_application_name, client_app_name, idle_period=30
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


def scp_file_preserve_ctime(
    juju: jubilant.Juju, substrate: Substrate, unit_name: str, path: str, container: str = "mongod"
) -> str:
    """Returns the filename that we've copied this file to."""
    # Retrieving the file
    filename = path.split("/")[-1]
    return_code = 0
    stderr = ""

    try:
        stdout = run_command_on_server(
            juju, substrate, unit_name, f"cat {path}", container=container
        )
    except jubilant.CLIError as e:
        return_code = e.returncode
        stderr = e.stderr
        logger.error(stderr)
        raise ProcessError(
            "Expected command %s to succeed instead it failed: %s; %s",
            f"cat {path}",
            return_code,
            stderr,
        )

    with open(filename, mode="w") as fd:
        fd.write(stdout.strip())

    return f"{filename}"


def check_if_test_documents_stored(
    juju: jubilant.Juju, substrate: Substrate, app_name: str, uri: str, collection: str
) -> None:
    """Check to see if some documents for the `TEST_DOCUMENT` dict were stored."""
    # serialize the str test documents into json
    o_test_docs = json.loads(TEST_DOCUMENTS)

    # query filter
    formatted_list = bson_dumps([{"uid": test_doc["uid"]} for test_doc in o_test_docs])
    # Needed to escape the $ properly
    query_filter = f"{{\\$or: {formatted_list}}}"

    count_documents = execute_on_mongod(
        juju,
        substrate=substrate,
        app_name=app_name,
        uri=uri,
        command=f"db.{collection}.countDocuments({query_filter})",
        expecting_output=True,
    )
    assert count_documents.data == 2

    # descending order to match insertion order of the test documents
    find_documents = execute_on_mongod(
        juju,
        substrate=substrate,
        app_name=app_name,
        uri=uri,
        command=f"db.{collection}.find({query_filter}).sort({{uid: 1}}).toArray()",
        expecting_output=True,
    )
    assert len(find_documents.data) == 2

    for index, test_doc in zip(range(len(o_test_docs)), o_test_docs):
        db_doc = find_documents.data[index]

        for key, val in test_doc.items():
            assert db_doc[key] == val


class DelayTuple(NamedTuple):
    uri: str
    delay: float


def secondary_mongo_uris_with_sync_delay(
    juju: jubilant.Juju,
    app_name: str,
    rs_status_data: dict[str, dict[str, str]],
) -> list[DelayTuple]:
    """Returns the list of secondaries and their sync delay with the master.

    Returns the ascending list of Secondaries, the first secondary is the
    one with the lowest data sync delay.
    """
    primary_optime_date = [
        datetime.strptime(member["optimeDate"], "%Y-%m-%dT%H:%M:%S.%fZ")
        for member in rs_status_data["members"]
        if member["stateStr"].upper() == "PRIMARY"
    ][0]

    secondaries: list[DelayTuple] = []
    for member in rs_status_data["members"]:
        if member["stateStr"].upper() != "SECONDARY":
            continue

        host = member["name"].split(":")[0]
        member_optime_date = datetime.strptime(member["optimeDate"], "%Y-%m-%dT%H:%M:%S.%fZ")

        username = CHARMED_OPERATOR_USERNAME
        password = get_password(juju, app_name, username)
        uri = unit_uri(username=username, password=password, ip_address=host, replica_set=None)
        delay_seconds = (primary_optime_date - member_optime_date).total_seconds()

        secondaries.append(DelayTuple(uri=uri, delay=math.fabs(delay_seconds)))

    secondaries.sort(key=lambda o: o.delay)

    return secondaries
