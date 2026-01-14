# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import math
import subprocess
from dataclasses import dataclass
from datetime import datetime
from random import choices
from string import ascii_lowercase, digits
from typing import Any
from urllib.parse import quote_plus

import yaml
from bson.json_util import dumps as bson_dumps
from dateutil.parser import parse
from juju.application import Application
from juju.client.client import FullStatus
from juju.model import Model
from juju.unit import Unit as JujuUnit
from pymongo import MongoClient
from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    retry,
    retry_if_result,
    stop_after_attempt,
    stop_after_delay,
    wait_exponential,
    wait_fixed,
)

from tests.integration.helpers.types import Substrate

MONGO_SHELL = "charmed-mongodb.mongosh"
MONGOD_PORT = 27017
MONGOS_PORT = 27018
UNIT_IDS = [0, 1, 2]
SERIES = "noble"
TIMEOUT = 15 * 60
DEPLOYMENT_TIMEOUT = 2000
CHARMED_BACKUP_USERNAME = "charmed-backup"
CHARMED_OPERATOR_USERNAME = "charmed-operator"
CHARMED_OPERATOR_PASSWORD = "operator-password"
CHARMED_STATS_USERNAME = "charmed-stats"
INTERNAL_USER_PASSWORD_CONFIG = "system-users"


CONTINUOUS_WRITE_APPLICATION = "continuous-write"
# Keep in sync with tests/integration/applications/continuous_write_charm/src/charm.py
DEFAULT_DATABASE_NAME = "continuous_writes_database"
DEFAULT_COLLECTION_NAME = "continuous_writes_collection"
DEFAULT_REPLICATION_COLL_NAME = "test_ubuntu_collection"

MEDIAN_REELECTION_TIME = 12

TEST_DOCUMENTS = """[
    {
        \"uid\": 123,
        \"label\": \"Lorem\",
        \"price\": 2.3,
        \"currency\": \"eur\",
        \"exp_date\": \"2022-12-12\"
    },
    {
        \"uid\": 3456,
        \"label\": \"Ipsum\",
        \"price\": 18,
        \"currency\": \"usd\",
        \"exp_date\": \"2023-01-13\"
    }
]"""


MONGOS_APP_NAME = "mongos"

DATA_INTEGRATOR_APP_NAME = "data-integrator"
logger = logging.getLogger(__name__)


def mongosh(substrate: Substrate) -> str:
    match substrate:
        case "lxd":
            return "charmed-mongodb.mongosh"
        case "microk8s":
            return "mongosh"


class ProcessError(Exception):
    """Raised when a process fails."""


class SecretNotFoundError(Exception):
    """Raised when a secret is not found."""


async def deploy_charm(
    ops_test: OpsTest,
    charm: str,
    substrate: Substrate,
    mongod_resource: dict,
    app_name: str,
    num_units: int = 3,
    channel: str | None = None,
    config: dict | None = None,
    subordinate: bool = False,
    storage: dict | None = None,
    series: str | None = None,
):
    if substrate == "microk8s":
        series = series or "noble"
        await ops_test.model.deploy(
            charm,
            resources=(mongod_resource if not channel else None),
            application_name=app_name,
            num_units=0 if subordinate else num_units,
            series=series,
            trust=True,
            config=config,
            channel=channel,
            storage=storage,
        )
    else:
        await ops_test.model.deploy(
            charm,
            num_units=0 if subordinate else num_units,
            application_name=app_name,
            config=config,
            channel=channel,
            storage=storage,
        )


async def deploy_application(
    ops_test: OpsTest,
    application_path: str,
    app_name: str,
):
    """Deploys the helpers applications with one unit and waits for idle."""
    application_name = await get_app_name(ops_test, app_name)
    if application_name:
        return
    await ops_test.model.deploy(
        application_path,
        application_name=app_name,
        num_units=1,
        series="noble",
    )
    # TODO: remove raise_on_error when we move to juju 3.5 (DPE-4996)
    await ops_test.model.wait_for_idle(
        apps=[app_name],
        raise_on_blocked=True,
        raise_on_error=False,
        timeout=DEPLOYMENT_TIMEOUT,
    )


async def relate_mongodb_and_application(
    ops_test: OpsTest, mongodb_application_name: str, application_name: str
) -> None:
    """Relates the mongodb and application charms.

    Args:
        ops_test: The ops test framework
        mongodb_application_name: The mongodb charm application name
        application_name: The continuous writes test charm application name
    """
    if is_relation_joined(ops_test, "database", "database"):
        return

    await ops_test.model.integrate(
        f"{application_name}:database", f"{mongodb_application_name}:database"
    )
    await ops_test.model.block_until(lambda: is_relation_joined(ops_test, "database", "database"))

    await ops_test.model.wait_for_idle(
        apps=[mongodb_application_name, application_name],
        status="active",
        raise_on_blocked=True,
        timeout=TIMEOUT,
    )


async def run_action(
    model: Model, application_name: str, action_name: str, **params: Any
) -> dict[str, str]:
    app: Application = model.applications[application_name]
    action = await app.units[0].run_action(action_name, **params)
    await action.wait()
    return action.results


async def get_address_of_unit(
    ops_test: OpsTest, substrate: Substrate, unit_id: int, app_name: str
) -> str:
    """Retrieves the address of the unit based on provided id."""
    status: FullStatus = await ops_test.model.get_status()
    if substrate == "microk8s":
        return status["applications"][app_name]["units"][f"{app_name}/{unit_id}"]["address"]
    return status["applications"][app_name]["units"][f"{app_name}/{unit_id}"]["public-address"]


async def generate_mongodb_client(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    mongos: bool,
    hosts: list[str] | None = None,
    username: str = CHARMED_OPERATOR_USERNAME,
    password: str | None = None,
):
    """Returns a MongoDB client for mongos/mongod."""
    hosts = hosts or [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    password = password or await get_password(ops_test, username, app_name=app_name)
    port = MONGOS_PORT if mongos else MONGOD_PORT
    hosts = [f"{host}:{port}" for host in hosts]
    hosts = ",".join(hosts)
    database = "admin"

    complement = ""
    if not mongos:
        complement = f"replicaSet={app_name}"

    return (
        f"mongodb://{username}:{quote_plus(password)}@{hosts}/{quote_plus(database)}?{complement}"
    )


async def mongodb_uri(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    unit_ids: list[int] | None = None,
    port: int = MONGOD_PORT,
    username: str = CHARMED_OPERATOR_USERNAME,
    password: str | None = None,
    hostnames: bool = False,
) -> str:
    """Build the URI for mongodb, to run on a charm unit (not from the host running the test)."""
    if unit_ids is None:
        unit_ids = range(0, len(ops_test.model.applications[app_name].units))

    if substrate == "microk8s" and hostnames:
        addresses = [f"{app_name}-{unit_id}.{app_name}-endpoints" for unit_id in unit_ids]
    else:
        addresses = [
            await get_address_of_unit(ops_test, substrate, unit_id, app_name)
            for unit_id in unit_ids
        ]

    hosts = [f"{host}:{port}" for host in addresses]
    hosts = ",".join(hosts)

    password = password or await get_password(ops_test, username=username, app_name=app_name)

    return f"mongodb://{username}:{password}@{hosts}/admin"


class Status:
    """Model class for status."""

    def __init__(self, value: str, since: str, message: str | None = None):
        self.value = value
        self.since = parse(since, ignoretz=True)
        self.message = message


class Unit:
    """Model class for a Unit, with properties widely used."""

    def __init__(
        self,
        id: int,
        name: str,
        ip: str,
        hostname: str,
        is_leader: bool,
        machine_id: int,
        workload_status: Status,
        agent_status: Status,
        app_status: Status,
    ):
        self.id = id
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.is_leader = is_leader
        self.machine_id = machine_id
        self.workload_status = workload_status
        self.agent_status = agent_status
        self.app_status = app_status

    def dump(self) -> dict[str, Any]:
        """To json."""
        result = {}
        for key, val in vars(self).items():
            result[key] = vars(val) if isinstance(val, Status) else val
        return result


async def destroy_cluster(
    ops_test: OpsTest, applications: list[str], destroy_storage: bool = False
) -> None:
    """Destroy cluster in a forceful way."""
    for app in applications:
        await ops_test.model.applications[app].destroy(
            destroy_storage=destroy_storage, force=True, no_wait=False
        )

    # destroy does not wait for applications to be removed, perform this check manually
    for attempt in Retrying(stop=stop_after_attempt(100), wait=wait_fixed(10), reraise=True):
        with attempt:
            # pytest_operator has a bug where the number of applications does not get correctly
            # updated. Wrapping the call with `fast_forward` resolves this
            async with ops_test.fast_forward():
                finished = all(item not in ops_test.model.applications for item in applications)
            # This case we don't raise an error in the context manager which fails to restore the
            # `update-status-hook-interval` value to it's former state.
            assert finished, "old cluster not destroyed successfully"


def unit_uri(
    ip_address: str,
    password: str,
    app: str,
    username: str = CHARMED_OPERATOR_USERNAME,
    mongos: bool = False,
) -> str:
    """Generates URI that is used by MongoDB to connect to a single replica.

    Args:
        ip_address: ip address of replica/unit
        password: password of database.
        app: name of application which has the cluster.
    """
    if mongos:
        return f"mongodb://{username}:{password}@{ip_address}:{MONGOS_PORT}/admin"
    return f"mongodb://{username}:{password}@{ip_address}:{MONGOD_PORT}/admin?replicaSet={app}"


async def get_password(
    ops_test: OpsTest,
    username=CHARMED_OPERATOR_USERNAME,
    app_name: str | None = None,
) -> str:
    """Retrieve the password for a given user from the application's Juju secret."""
    app_name = app_name or await get_app_name(ops_test)
    secret = await get_secret_by_label(ops_test, label=f"{app_name}.app")
    return secret.get(f"{username}-password")


async def get_secret_by_label(ops_test: OpsTest, label: str) -> dict[str, str]:
    secrets_raw = await ops_test.juju("list-secrets")
    secret_ids = [
        secret_line.split()[0] for secret_line in secrets_raw[1].split("\n")[1:] if secret_line
    ]

    for secret_id in secret_ids:
        secret_data_raw = await ops_test.juju(
            "show-secret", "--format", "json", "--reveal", secret_id
        )
        secret_data = json.loads(secret_data_raw[1])

        if label == secret_data[secret_id].get("label"):
            return secret_data[secret_id]["content"]["Data"]

    raise SecretNotFoundError(f"Secret with label {label} not found.")


@retry(
    retry=retry_if_result(lambda x: x == 0),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=30),
)
async def count_primaries(
    ops_test: OpsTest, substrate: Substrate, password: str, app_name: str | None = None
) -> int:
    """Counts the number of primaries in a replica set.

    Will retry counting when the number of primaries is 0 at most 5 times.
    """
    app_name = app_name or await get_app_name(ops_test)
    number_of_primaries = 0
    for unit in ops_test.model.applications[app_name].units:
        unit_id = get_unit_id(unit.name)
        # get unit
        ip_address = await get_address_of_unit(ops_test, substrate, unit_id, app_name)

        # connect to mongod
        client = MongoClient(unit_uri(ip_address, password, app_name), directConnection=True)

        # check primary status
        if client.is_primary:
            number_of_primaries += 1

    return number_of_primaries


async def get_direct_mongo_client(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    mongos: bool = False,
    unit: JujuUnit | None = None,
    username: str | None = None,
    password: str | None = None,
) -> MongoClient:
    """Gets a direct mongodb client.

    This is direct as it connects to one host only, by default the leader unit,
    otherwise the provided unit. It does not connect to a replica set.
    The reason behind that is that on kubernetes, we would fail to connect to a
    replica set from the host because of the server selection that relies on
    the registered hosts in mongodb and not the one provided in the URI. Here,
    we create the mongo client using the unit IP (not host) so that we can
    connect to both kubernetes and VM.
    """
    unit = unit or await find_unit(ops_test, leader=True, app_name=app_name)
    ip_address = await get_address_of_unit(ops_test, substrate, get_unit_id(unit.name), app_name)
    match username, password:
        case None, None:
            username = CHARMED_OPERATOR_USERNAME
            password = await get_password(ops_test, CHARMED_OPERATOR_USERNAME, app_name=app_name)
        case _, None:
            raise Exception("Please provide username and password")
        case None, _:
            raise Exception("Please provide username and password")
        case _:
            pass

    return MongoClient(
        unit_uri(ip_address, password, app_name, username=username, mongos=mongos),
        directConnection=True,
    )


async def find_unit(ops_test: OpsTest, leader: bool, app_name: str | None = None) -> JujuUnit:
    """Helper function identifies the a unit, based on need for leader or non-leader."""
    app_name = app_name or await get_app_name(ops_test)
    ret_unit = None
    for unit in ops_test.model.applications[app_name].units:
        if await unit.is_leader_from_status() == leader:
            ret_unit = unit

    return ret_unit


async def get_leader_id(ops_test: OpsTest, app_name=None) -> int:
    """Returns the unit number of the juju leader unit."""
    app_name = app_name or await get_app_name(ops_test)
    for unit in ops_test.model.applications[app_name].units:
        if await unit.is_leader_from_status():
            return int(unit.name.split("/")[1])
    return -1


async def set_password(
    ops_test: OpsTest,
    username: str,
    password: str,
    app_name: str,
) -> None:
    """Set a user password via secret.

    Beware that if the function is called, subsequently, the secret will only
    keep the content of the username in the latest call.

    Args:
        ops_test: ops_test instance.
        username: the user to set the password.
        password: password to use
        app_name: the application the created secret will be granted to
    """
    secret_name = f"system_users_secret_{app_name}"

    try:
        secret_id = await ops_test.model.add_secret(
            name=secret_name, data_args=[f"{username}={password}"]
        )
    except Exception:
        secrets = await ops_test.model.list_secrets({"label": secret_name})
        secret_id = secrets[0].uri
        await ops_test.model.update_secret(
            name=secret_name, data_args=[f"{username}={password}"], new_name=secret_name
        )

    await ops_test.model.grant_secret(secret_name=secret_name, application=app_name)

    # update the application config to include the secret
    logger.info(
        f"Setting the {INTERNAL_USER_PASSWORD_CONFIG} config in {app_name} to {secret_id} {username}={password}"
    )
    await ops_test.model.applications[app_name].set_config(
        {INTERNAL_USER_PASSWORD_CONFIG: secret_id}
    )


async def get_application_relation_data(
    ops_test: OpsTest,
    application_name: str,
    relation_name: str,
    key: str,
    relation_id: str | None = None,
    relation_alias: str | None = None,
) -> str | None:
    """Get relation data for an application.

    Args:
        ops_test: The ops test framework instance
        application_name: The name of the application
        relation_name: name of the relation to get connection data from
        key: key of data to be retrieved
        relation_id: id of the relation to get connection data from
        relation_alias: alias of the relation (like a connection name)
            to get connection data from
    Returns:
        the that that was requested or None
            if no data in the relation
    Raises:
        ValueError if it's not possible to get application unit data
            or if there is no data for the particular relation endpoint
            and/or alias.
    """
    unit = await find_unit(ops_test, leader=True, app_name=application_name)
    unit_name = unit.name
    raw_data = (await ops_test.juju("show-unit", unit_name))[1]

    if not raw_data:
        raise ValueError(f"no unit info could be grabbed for {unit_name}")
    data = yaml.safe_load(raw_data)

    # Filter the data based on the relation name.
    relation_data = [v for v in data[unit_name]["relation-info"] if v["endpoint"] == relation_name]
    if relation_id:
        # Filter the data based on the relation id.
        relation_data = [v for v in relation_data if v["relation-id"] == relation_id]

    if relation_alias:
        # Filter the data based on the cluster/relation alias.
        relation_data = [
            v
            for v in relation_data
            if json.loads(v["application-data"]["data"])["alias"] == relation_alias
        ]

    if len(relation_data) == 0:
        raise ValueError(
            f"no relation data could be grabbed on relation with endpoint {relation_name} and alias {relation_alias}"
        )

    return relation_data[0]["application-data"].get(key)


async def get_secret_id(ops_test, app_or_unit: str | None = None) -> str:
    """Retrieve secret ID for an app or unit."""
    complete_command = "list-secrets"

    if app_or_unit:
        prefix = "unit" if app_or_unit[-1].isdigit() else "application"
        formated_app_or_unit = f"{prefix}-{app_or_unit}"
        if prefix == "unit":
            formated_app_or_unit = formated_app_or_unit.replace("/", "-")
        complete_command += f" --owner {formated_app_or_unit}"

    _, stdout, _ = await ops_test.juju(*complete_command.split())
    output_lines_split = [line.split() for line in stdout.strip().split("\n")]
    if app_or_unit:
        return [line[0] for line in output_lines_split if app_or_unit in line][0]

    return output_lines_split[1][0]


async def get_secret_content(ops_test, secret_id) -> dict[str, str]:
    """Retrieve contents of a Juju Secret."""
    secret_id = secret_id.split("/")[-1]
    complete_command = f"show-secret {secret_id} --reveal --format=json"
    _, stdout, _ = await ops_test.juju(*complete_command.split())
    data = json.loads(stdout)
    return data[secret_id]["content"]["Data"]


async def check_or_scale_app(
    ops_test: OpsTest, substrate: Substrate, user_app_name: str, required_units: int
) -> None:
    """A helper function that scales existing cluster if necessary."""
    # check if we need to scale
    current_units = len(ops_test.model.applications[user_app_name].units)

    if current_units == required_units:
        return

    if substrate == "microk8s":
        count = required_units - current_units
        await ops_test.model.applications[user_app_name].scale(scale_change=count)
        await ops_test.model.wait_for_idle()
        return

    if current_units > required_units:
        for i in range(0, current_units):
            unit_to_remove = [ops_test.model.applications[user_app_name].units[i].name]
            await ops_test.model.destroy_units(*unit_to_remove)
            await ops_test.model.wait_for_idle()
    else:
        units_to_add = required_units - current_units
        await ops_test.model.applications[user_app_name].add_unit(count=units_to_add)
        await ops_test.model.wait_for_idle()


async def remove_units(
    ops_test: OpsTest, substrate: Substrate, app_name: str, units: list[JujuUnit]
):
    """Removes the correct units (number of units for kubernetes."""
    if substrate == "lxd":
        await ops_test.model.applications[app_name].destroy_unit(*(unit.name for unit in units))
    else:
        count = len(units)
        await ops_test.model.applications[app_name].scale(scale_change=-count)


async def get_app_name(
    ops_test: OpsTest, charm_name: str = "mongodb", test_deployments: list[str] = []
) -> str:
    """Returns the name of the cluster running MongoDB.

    This is important since not all deployments of the MongoDB charm have the application name
    "mongodb".

    Note: if multiple clusters are running MongoDB this will return the one first found.
    """
    status = await ops_test.model.get_status()
    for app in ops_test.model.applications:
        # note that format of the charm field is not exactly "mongodb" but instead takes the form
        # of `local:focal/mongodb-6`
        if charm_name in status["applications"][app]["charm"]:
            logger.debug("Found %s app named '%s'", charm_name, app)

            if app in test_deployments:
                logger.debug(
                    "%s app named '%s', was deployed by the test, not by user", charm_name, app
                )
                continue

            return app

    return None


async def unit_hostname(ops_test: OpsTest, unit_name: str) -> str:
    """Get hostname for a unit.

    Args:
        ops_test: The ops test object passed into every test case
        unit_name: The name of the unit to be tested

    Returns:
        The machine/container hostname
    """
    _, raw_hostname, _ = await ops_test.juju("ssh", unit_name, "hostname")
    return raw_hostname.strip()


def instance_ip(model: str, instance: str) -> str:
    """Translate juju instance name to IP.

    Args:
        model: The name of the model
        instance: The name of the instance

    Returns:
        The (str) IP address of the instance
    """
    output = subprocess.check_output(f"juju machines --model {model}".split())

    for line in output.decode("utf8").splitlines():
        if instance in line:
            return line.split()[2]

    return ""


def audit_log_line_sanity_check(entry) -> bool:
    fields = ["atype", "ts", "local", "remote", "users", "roles", "param", "result"]
    for field in fields:
        if entry.get(field) is None:
            logger.error("Field '%s' not found in audit log entry \"%s\"", field, entry)
            return False
    return True


async def get_unit_hostname(ops_test: OpsTest, unit_id: int, app: str) -> str:
    """Get the hostname of a specific unit."""
    _, hostname, _ = await ops_test.juju("ssh", f"{app}/{unit_id}", "hostname")
    return hostname.strip()


async def get_unit_hostnames(ops_test: OpsTest, substrate: Substrate, app_name: str) -> list[str]:
    if substrate == "microk8s":
        return [
            f"{unit.name.replace('/', '-')}.{app_name}-endpoints"
            for unit in ops_test.model.applications[app_name].units
        ]

    return [
        await get_address_of_unit(ops_test, substrate, get_unit_id(unit.name), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]


async def get_mongodb_hostname_for_unit(ops_test: OpsTest, substrate: Substrate, unit_name: str):
    """Get the hostname for a unit in mongodb."""
    unit_id, app_name = get_unit_app(unit_name)
    if substrate == "lxd":
        return await get_address_of_unit(ops_test, substrate, unit_id, app_name)
    return f"{unit_name.replace('/', '-')}.{app_name}-endpoints"


async def get_raw_application(ops_test: OpsTest, app: str) -> dict[str, Any]:
    """Get raw application details."""
    ret_code, stdout, stderr = await ops_test.juju(
        *f"status --model {ops_test.model.info.name} {app} --format=json".split()
    )
    if ret_code != 0:
        logger.error(f"Invalid return [{ret_code=}]: {stderr=}")
        raise Exception(f"[{ret_code=}] {stderr=}")
    return json.loads(stdout)["applications"][app]


async def get_application_units(ops_test: OpsTest, substrate: Substrate, app: str) -> list[Unit]:
    """Get fully detailed units of an application."""
    raw_app = await get_raw_application(ops_test, app)
    units = []
    for u_name, unit in raw_app["units"].items():
        unit_id = int(u_name.split("/")[-1])

        if substrate == "lxd" and not (address := unit.get("public-address")):
            # unit not ready yet...
            continue

        if substrate == "microk8s" and not (address := unit.get("address")):
            # unit not ready yet...
            continue

        unit = Unit(
            id=unit_id,
            name=u_name.replace("/", "-"),
            ip=address,
            hostname=await get_unit_hostname(ops_test, unit_id, app),
            is_leader=unit.get("leader", False),
            machine_id=int(unit["machine"]) if substrate == "lxd" else -1,
            workload_status=Status(
                value=unit["workload-status"]["current"],
                since=unit["workload-status"]["since"],
                message=unit["workload-status"].get("message"),
            ),
            agent_status=Status(
                value=unit["juju-status"]["current"],
                since=unit["juju-status"]["since"],
            ),
            app_status=Status(
                value=raw_app["application-status"]["current"],
                since=raw_app["application-status"]["since"],
                message=raw_app["application-status"].get("message"),
            ),
        )

        units.append(unit)

    return units


async def assert_subordinate_blocked_with_status(
    ops_test: OpsTest, app_name: str, status: str | None
) -> None:
    """Checks if all units are blocked with a provided status.

    The command juju status --model {model-name} {app-name} --json does not provide information
    for statuses for subordinate charms like it does for normal charms. Specifically when
    converting to json it lose this information. To get this information we must parse the status
    manually.
    """
    juju_status = (
        subprocess.check_output(
            f"juju status --model {ops_test.model.info.name} {app_name}".split()
        )
        .decode("utf-8")
        .split("\n")
    )

    for status_line in juju_status:
        if not status_line:
            continue
        if app_name not in status_line:
            continue
        # no need to check that status of the application since the application can have a
        # different status than the units.
        component_name = status_line.split(" ")[0]
        is_app = "/" not in component_name
        if is_app:
            continue

        status_line = status_line.split()
        unit_name = status_line[0]
        status_type = status_line[1]
        status_message = " ".join(status_line[4:])
        assert status_type == "blocked", f"unit {unit_name} not in blocked state, in {status_type}"

        if status:
            # Port can be open and it would make parsing hard.
            assert (
                status in status_message
            ), f"unit {unit_name} does not show the status '{status}',has message '{status_message}'"


async def check_all_units_blocked_with_status(
    ops_test: OpsTest,
    substrate: Substrate,
    db_app_name: str,
    status: str | None,
    subordinate: bool = False,
) -> None:
    # this is necessary because ops_model.units does not update the unit statuses
    if subordinate:
        await assert_subordinate_blocked_with_status(ops_test, db_app_name, status)
        return
    for unit in await get_application_units(ops_test, substrate, db_app_name):
        assert (
            unit.workload_status.value == "blocked"
        ), f"unit {unit.name} not in blocked state, in {unit.workload_status.value}"
        if status:
            assert (
                status in unit.workload_status.message
            ), f"unit {unit.name} status is `{unit.workload_status.message}`, expected `{status}`"


async def wait_for_mongodb_units_blocked(
    ops_test: OpsTest,
    substrate: Substrate,
    db_app_name: str,
    status: str | None = None,
    timeout=20,
    subordinate: bool = False,
) -> None:
    """Waits for units of MongoDB to be in the blocked state.

    This is necessary because the MongoDB app can report a different status than the units.
    """
    units = ops_test.model.applications[db_app_name].units
    await ops_test.model.block_until(
        *[lambda: unit.workload_status == "blocked" for unit in units], timeout=TIMEOUT
    )
    hook_interval_key = "update-status-hook-interval"
    try:
        old_interval = (await ops_test.model.get_config())[hook_interval_key]
        await ops_test.model.set_config({hook_interval_key: "1m"})
        for attempt in Retrying(stop=stop_after_delay(timeout), wait=wait_fixed(1), reraise=True):
            with attempt:
                await check_all_units_blocked_with_status(
                    ops_test, substrate, db_app_name, status, subordinate
                )
    finally:
        await ops_test.model.set_config({hook_interval_key: old_interval})


async def check_status_detail(ops_test: OpsTest, app_name: str, status: str, message: str) -> None:
    """Checks that the first status returned by status-detail is the one expected."""
    for unit in ops_test.model.applications[app_name].units:
        action = await unit.run_action("status-detail")
        action = await action.wait()
        result = action.results["json-output"]

        # juju messes up the string formatting here.
        unit_statuses = json.loads(result["unit"])
        assert (
            unit_statuses[0]["Status"].lower() == status
        ), f"unit {unit.name} status is `{unit_statuses[0]['Status'].lower()}`, expected `{status}`"
        assert (
            unit_statuses[0]["Message"] == message
        ), f"unit {unit.name} status is `{unit_statuses[0]['Message']}`, expected `{message}`"


async def get_status_detail(unit: JujuUnit) -> dict:
    action = await unit.run_action("status-detail")
    action = await action.wait()
    return action.results["json-output"]


async def check_app_status(
    ops_test: OpsTest, app_name: str, status: str, message: str | None = None
) -> None:
    """Checks that the application has the correct status and message."""
    app = ops_test.model.applications[app_name]
    await ops_test.model.block_until(*[lambda: app.status == status], timeout=TIMEOUT)
    if message:
        assert app.status_message == message


def is_relation_joined(ops_test: OpsTest, endpoint_one: str, endpoint_two: str) -> bool:
    """Check if a relation is joined.

    Args:
        ops_test: The ops test object passed into every test case
        endpoint_one: The first endpoint of the relation
        endpoint_two: The second endpoint of the relation
    """
    for rel in ops_test.model.relations:
        endpoints = [endpoint.name for endpoint in rel.endpoints]
        if endpoint_one in endpoints and endpoint_two in endpoints:
            return True
    return False


@dataclass(frozen=True)
class CommandResult:
    return_code: int
    stdout: str
    stderr: str
    data: Any

    @property
    def succeeded(self):
        return self.return_code == 0

    @property
    def failed(self):
        return self.return_code != 0


async def execute_on_mongod(
    ops_test: OpsTest,
    app_name: str,
    substrate: Substrate,
    uri: str,
    command: str,
    container_name: str = "mongod",
    stringify: bool = True,
    expecting_output: bool = True,
) -> CommandResult:
    """Executes the command with mongosh."""
    leader_id = await get_leader_id(ops_test, app_name)
    ssh_command = ["ssh", "--container", container_name] if substrate == "microk8s" else ["ssh"]

    if stringify:
        formatted_string = f'"{uri}" --quiet --eval "EJSON.stringify({command})"'
    else:
        formatted_string = f'"{uri}" --quiet --eval "{command}"'

    cmd = [f"{app_name}/{leader_id}", mongosh(substrate), formatted_string]

    ret_code, stdout, stderr = await ops_test.juju(*(ssh_command + cmd))

    logger.info("ret_code: %s, stdout: %s, stderr: %s", ret_code, stdout, stderr)

    if ret_code != 0:
        logger.error(f"Failed to execute {command}: {stderr=}, {stdout=}")

    if not ret_code:
        ret_code = 0

    data = None
    if expecting_output:
        try:
            data = json.loads(stdout.split("\x07")[-1])
        except json.JSONDecodeError:
            pass

    return CommandResult(
        return_code=ret_code,
        stderr=stderr,
        stdout=stdout,
        data=data,
    )


async def start_continous_writes(
    ops_test: OpsTest,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
):
    """Helper function to run the `start-continuous-write` action on the continuous write app."""
    application_unit = ops_test.model.applications[client_app_name].units[0]
    start_writes_action = await application_unit.run_action(
        "start-continuous-writes", **{"db-name": db_name, "collection-name": coll_name}
    )
    await start_writes_action.wait()


async def stop_continous_writes(
    ops_test: OpsTest,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
) -> int:
    """Helper function to run the `stop-continuous-write` action on the continuous write app.

    It returns the number of writes.
    """
    application_unit = ops_test.model.applications[client_app_name].units[0]
    stop_writes_action = await application_unit.run_action(
        "stop-continuous-writes", **{"db-name": db_name, "collection-name": coll_name}
    )
    await stop_writes_action.wait()
    return int(stop_writes_action.results["writes"])


async def clear_continous_writes(
    ops_test: OpsTest,
    client_app_name: str,
    db_name: str = DEFAULT_DATABASE_NAME,
    coll_name: str = DEFAULT_COLLECTION_NAME,
):
    """Helper function to run the `clear-continuous-write` action on the continuous write app."""
    application_unit = ops_test.model.applications[client_app_name].units[0]
    clear_writes_action = await application_unit.run_action(
        "clear-continuous-writes", **{"db-name": db_name, "collection-name": coll_name}
    )
    await clear_writes_action.wait()


async def count_writes(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    unit: JujuUnit,
    mongos: bool = False,
    username: str = CHARMED_OPERATOR_USERNAME,
) -> int:
    """New versions of pymongo no longer support the count operation, instead find is used."""
    host = await get_address_of_unit(ops_test, substrate, get_unit_id(unit.name), app_name=app_name)
    uri = await generate_mongodb_client(
        ops_test,
        substrate,
        app_name,
        mongos=mongos,
        hosts=[host],
        username=username,
    )

    client = MongoClient(uri, directConnection=True)
    db = client[DEFAULT_DATABASE_NAME]
    test_collection = db[DEFAULT_COLLECTION_NAME]
    count = test_collection.count_documents({})
    client.close()
    return count


def generate_collection_id() -> str:
    """Generates a random collection id."""
    new_id = "".join(choices(ascii_lowercase + digits, k=4)).replace("_", "")
    return f"collection_{new_id}"


async def check_if_test_documents_stored(
    ops_test: OpsTest, app_name: str, substrate: Substrate, uri: str, collection: str
) -> None:
    """Check to see if some documents for the `TEST_DOCUMENT` dict were stored."""
    # serialize the str test documents into json
    o_test_docs = json.loads(TEST_DOCUMENTS)

    # query filter
    formatted_list = bson_dumps([{"uid": test_doc["uid"]} for test_doc in o_test_docs])
    # Needed to escape the $ properly
    query_filter = f"{{\\$or: {formatted_list}}}"

    count_documents = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        f"db.{collection}.countDocuments({query_filter})",
    )
    assert count_documents.data == 2

    # descending order to match insertion order of the test documents
    find_documents = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        f"db.{collection}.find({query_filter}).sort({{uid: 1}}).toArray()",
    )
    assert len(find_documents.data) == 2

    for index, test_doc in zip(range(len(o_test_docs)), o_test_docs):
        db_doc = find_documents.data[index]

        for key, val in test_doc.items():
            assert db_doc[key] == val


def get_unit_id(unit_name: str) -> int:
    """Unit id from unit name."""
    return int(unit_name.split("/")[1])


def get_app_name_from_unit(unit_name: str) -> str:
    """Gets the app name from a unit name."""
    return unit_name.split("/")[0]


def get_unit_app(unit_name) -> tuple[int, str]:
    """Returns the unit id and app name from the unit name."""
    return (get_unit_id(unit_name), get_app_name_from_unit(unit_name))


def get_unit_id_from_host(units: dict[int, str], host: str) -> int:
    """Gets the unit id from the dictionary mapping unit ids to hosts."""
    for unit_id, _host in units.items():
        if host == _host:
            return unit_id
    raise Exception("no host found", units, host)


async def secondary_mongo_uris_with_sync_delay(
    ops_test: OpsTest, substrate: Substrate, app_name: str, rs_status_data: dict
):
    """Returns the list of secondaries and their sync delay with the master.

    Returns the ascending list of Secondaries, the first secondary is the
    one with the lowest data sync delay.
    """
    if substrate == "lxd":
        hosts = {
            get_unit_id(unit.name): await get_address_of_unit(
                ops_test, substrate, get_unit_id(unit.name), app_name
            )
            for unit in ops_test.model.applications[app_name].units
        }
    else:
        hosts = {
            get_unit_id(unit.name): f"{unit.name.replace('/', '-')}.mongodb-k8s-endpoints"
            for unit in ops_test.model.applications[app_name].units
        }

    primary_optime_date = [
        datetime.strptime(member["optimeDate"], "%Y-%m-%dT%H:%M:%S.%fZ")
        for member in rs_status_data["members"]
        if member["stateStr"].upper() == "PRIMARY"
    ][0]

    secondaries = []
    for member in rs_status_data["members"]:
        if member["stateStr"].upper() != "SECONDARY":
            continue

        unit_id = get_unit_id_from_host(hosts, member["name"].split(":")[0])
        member_optime_date = datetime.strptime(member["optimeDate"], "%Y-%m-%dT%H:%M:%S.%fZ")

        host = await mongodb_uri(ops_test, substrate, app_name, unit_ids=[unit_id])
        delay_seconds = (primary_optime_date - member_optime_date).total_seconds()

        secondaries.append({"uri": host, "delay": math.fabs(delay_seconds)})

    secondaries.sort(key=lambda o: o["delay"])

    return secondaries


async def get_secret_data(ops_test: OpsTest, secret_uri: str):
    """Gets the data stored in a secret identified by its secret uri."""
    secret_unique_id = secret_uri.split("/")[-1]
    complete_command = f"show-secret {secret_uri} --reveal --format=json"
    _, stdout, _ = await ops_test.juju(*complete_command.split())
    return json.loads(stdout)[secret_unique_id]["content"]["Data"]


async def get_connection_string(
    ops_test: OpsTest,
    app_name: str,
    relation_name: str,
    relation_id: str | None = None,
    relation_alias: str | None = None,
) -> str:
    secret_uri = await get_application_relation_data(
        ops_test, app_name, relation_name, "secret-user", relation_id, relation_alias
    )
    assert secret_uri, "No secret URI found"

    first_relation_user_data = await get_secret_data(ops_test, secret_uri)
    return first_relation_user_data.get("uris")


def mongodb_log_path(substrate: Substrate) -> str:
    """The path of mongodb log file."""
    if substrate == "lxd":
        mongodb_common_dir = "/var/snap/charmed-mongodb/common"
    else:
        mongodb_common_dir = ""

    return f"{mongodb_common_dir}/var/log/mongodb/mongodb.log"


async def mongod_ready(ops_test: OpsTest, unit_ip: str, app_name: str) -> bool:
    """Verifies replica is running and available."""
    app_name = app_name or await get_app_name(ops_test)
    password = await get_password(ops_test, CHARMED_OPERATOR_USERNAME, app_name=app_name)
    client = MongoClient(unit_uri(unit_ip, password, app_name), directConnection=True)
    try:
        for attempt in Retrying(stop=stop_after_delay(60 * 5), wait=wait_fixed(3)):
            with attempt:
                # The ping command is cheap and does not require auth.
                client.admin.command("ping")
    except RetryError:
        return False
    finally:
        client.close()

    return True


def get_juju_status(model_name: str, app_name: str) -> str:
    """Gets the juju status as a string."""
    return subprocess.check_output(f"juju status --model {model_name} {app_name}".split()).decode(
        "utf-8"
    )


async def get_relation_username_password(
    ops_test: OpsTest, app_name: str, relation_name: str
) -> tuple[str, str]:
    """Gets both usename and password stored in a relation."""
    secret_uri = await get_application_relation_data(
        ops_test, app_name, relation_name, "secret-user"
    )
    assert secret_uri, "No secret URI found"

    relation_user_data = await get_secret_data(ops_test, secret_uri)
    username = relation_user_data.get("username")
    password = relation_user_data.get("password")
    return (username, password)


def get_highest_unit(ops_test: OpsTest, app_name: str) -> JujuUnit | None:
    """Retrieves the most recently added unit to the MongoDB application."""
    num_units = len(ops_test.model.applications[app_name].units)
    highest_unit_name = f"{app_name}/{num_units - 1}"
    for unit in ops_test.model.applications[app_name].units:
        if unit.name == highest_unit_name:
            return unit
    return None


async def has_file(
    ops_test: OpsTest,
    substrate: Substrate,
    unit: JujuUnit,
    dir_path: str,
    filename: str,
    container: str = "mongod",
) -> bool:
    """Checks if the file exists or not."""
    app_name = get_app_name_from_unit(unit.name)
    match substrate:
        case "lxd":
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh {app_name}/leader sudo"
        case "microk8s":
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh --container {container} {app_name}/leader"
        case _:
            raise Exception(f"Invalid substrate {substrate}")

    files = subprocess.check_output(
        f"{base_command} ls {dir_path}",
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True,
    )
    return filename in files


async def execute_on_server(
    ops_test: OpsTest,
    substrate: Substrate,
    unit: JujuUnit,
    command: str,
    container: str = "mongod",
) -> str:
    """Executes a command on the server."""
    app_name = get_app_name_from_unit(unit.name)
    match substrate:
        case "lxd":
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh {app_name}/leader sudo"
        case "microk8s":
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh --container {container} {app_name}/leader"
        case _:
            raise Exception(f"Invalid substrate {substrate}")

    return subprocess.check_output(
        f"{base_command} {command}",
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True,
    )
