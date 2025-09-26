#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""High availability helpers."""

import json
import os
import string
import subprocess
import tarfile
import tempfile
from datetime import datetime
from logging import getLogger
from pathlib import Path

import kubernetes as kubernetes
import yaml
from juju.unit import Unit as JujuUnit
from more_itertools import one
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

from ..helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    DEFAULT_DATABASE_NAME,
    DEFAULT_REPLICATION_COLL_NAME,
    OPERATOR_USERNAME,
    TIMEOUT,
    ProcessError,
    count_primaries,
    count_writes,
    execute_on_mongod,
    find_unit,
    generate_mongodb_client,
    get_address_of_unit,
    get_app_name,
    get_direct_mongo_client,
    get_mongodb_hostname_for_unit,
    get_password,
    get_unit_id,
    instance_ip,
    mongodb_log_path,
    stop_continous_writes,
    unit_uri,
)
from ..helpers.types import Substrate

logger = getLogger(__name__)

VM_DB_PROCESS = "/usr/bin/mongod"
K8S_DB_PROCESS = "mongod"
MONGOD_SERVICE_DEFAULT_PATH = "/etc/systemd/system/snap.charmed-mongodb.mongod.service"


class ProcessRunningError(Exception):
    """Raised when a process is running when it is not expected to be."""


def cut_network_from_unit(ops_test: OpsTest, substrate: Substrate, machine_name: str) -> None:
    """Cut network from a lxc container.

    Args:
        machine_name: lxc container hostname or pod
    """
    if substrate == "lxd":
        # apply a mask (device type `none`)
        cut_network_command = f"lxc config device add {machine_name} eth0 none"
        subprocess.check_call(cut_network_command.split())
    else:
        # Apply a NetworkChaos file to use chaos-mesh to simulate a network cut.
        with tempfile.NamedTemporaryFile(dir=".") as temp_file:
            # Generates a manifest for chaosmesh to simulate network failure for a pod
            with open(
                "tests/integration/helpers/manifests/chaos_network_loss.yml"
            ) as chaos_network_loss_file:
                logger.info(
                    f"Calling network loss on ns={ops_test.model.info.name} and pod={machine_name.replace('/', '-')}"
                )
                template = string.Template(chaos_network_loss_file.read())
                chaos_network_loss = template.substitute(
                    namespace=ops_test.model.info.name,
                    pod=machine_name.replace("/", "-"),
                )

                temp_file.write(str.encode(chaos_network_loss))
                temp_file.flush()

            # Apply the generated manifest, chaosmesh would then make the pod inaccessible
            env = os.environ
            env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")
            try:
                command_result = subprocess.check_output(
                    " ".join(["microk8s", "kubectl", "apply", "-f", temp_file.name]),
                    shell=True,
                    env=env,
                    stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as err:
                logger.error(
                    f"Failed to apply network isolation: [{err.returncode}] {err.stderr=}, {err.stdout=}"
                )
                raise
            logger.info("Result of isolating unit from cluster is '%s'", command_result)


def restore_network_for_unit(ops_test: OpsTest, substrate: Substrate, machine_name: str) -> None:
    """Restore network from a lxc container.

    Args:
        machine_name: lxc container hostname
    """
    if substrate == "lxd":
        # remove mask from eth0
        restore_network_command = f"lxc config device remove {machine_name} eth0"
        subprocess.check_call(restore_network_command.split())
    else:
        env = os.environ
        env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")
        subprocess.check_output(
            f"microk8s kubectl -n {ops_test.model.info.name} delete networkchaos network-loss-primary",
            shell=True,
            env=env,
        )


@retry(stop=stop_after_attempt(60), wait=wait_fixed(15))
async def wait_network_restore(
    ops_test: OpsTest,
    substrate: Substrate,
    model_name: str,
    app_name: str,
    hostname: str,
    old_ip: str,
) -> None:
    """Wait until network is restored.

    Args:
        model_name: The name of the model
        hostname: The name of the instance
        old_ip: old registered IP address
    """
    if substrate == "lxd":
        if instance_ip(model_name, hostname) == old_ip:
            raise Exception("Network not restored, IP address has not changed yet.")
    else:
        # Wait for the network to be restored
        await ops_test.model.wait_for_idle(
            apps=[app_name], status="active", raise_on_blocked=False, timeout=1000
        )


def deploy_chaos_mesh(namespace: str) -> None:
    """Deploy chaos mesh to the provided namespace.

    Chaos mesh can them be used by the tests to simulate a variety of failures.

    Args:
        namespace: The namespace to deploy chaos mesh to
    """
    env = os.environ
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")

    subprocess.check_output(
        " ".join(
            [
                "tests/integration/helpers/scripts/deploy_chaos_mesh.sh",
                namespace,
            ]
        ),
        shell=True,
        env=env,
    )


def destroy_chaos_mesh(namespace: str) -> None:
    """Destroy chaos mesh on a provided namespace.

    Cleans up the test K8S from test related dependencies.

    Args:
        namespace: The namespace to deploy chaos mesh to
    """
    env = os.environ
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")

    subprocess.check_output(
        f"tests/integration/helpers/scripts/destroy_chaos_mesh.sh {namespace}",
        shell=True,
        env=env,
    )


@retry(stop=stop_after_attempt(10), wait=wait_fixed(5), reraise=True)
async def wait_until_unit_in_status(
    ops_test: OpsTest,
    substrate: Substrate,
    unit_to_check: JujuUnit,
    online_unit: JujuUnit,
    status: str,
    app_name: str,
):
    with await get_direct_mongo_client(ops_test, substrate, app_name, unit=online_unit) as client:
        data = client.admin.command("replSetGetStatus")
        for member in data["members"]:
            unit_name = host_to_unit(member["name"].split(":")[0])
            unit_hostname = await get_mongodb_hostname_for_unit(
                ops_test, substrate, unit_to_check.name
            )
            if substrate == "microk8s" and unit_to_check.name == unit_name:
                assert (
                    member["stateStr"] == status
                ), f"{unit_to_check.name} status is not {status}. Actual status: {member['stateStr']}"
                return
            if substrate == "lxd" and unit_hostname == member["name"].split(":")[0]:
                assert (
                    member["stateStr"] == status
                ), f"{unit_to_check.name} status is not {status}. Actual status: {member['stateStr']}"
                return
        assert False, f"{unit_to_check.name} not found"


async def fetch_primary(
    replica_set_hosts: list[str],
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
) -> str | None:
    """Returns IP address of current replica set primary."""
    password = await get_password(
        ops_test,
        username=OPERATOR_USERNAME,
        app_name=app_name,
    )

    uri = await generate_mongodb_client(
        ops_test, substrate, app_name, mongos=False, hosts=replica_set_hosts, password=password
    )

    # grab the replica set status
    result = await execute_on_mongod(ops_test, app_name, substrate, uri, "rs.status()")

    if result.failed:
        return None

    primary = None
    # loop through all members in the replica set
    for member in result.data["members"]:
        # check replica's current state
        if member["stateStr"] == "PRIMARY":
            # get member ip without ":PORT"
            primary = member["name"].split(":")[0]
            break

    return primary


def host_to_unit(host: str | None) -> str | None:
    return "/".join(host.split(".")[0].rsplit("-", 1)) if host else None


@retry(
    retry=retry_if_result(lambda x: x is None),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=30),
)
async def replica_set_primary(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    replica_set_hosts: list[str],
) -> JujuUnit | None:
    """Returns the primary of the replica set.

    Retrying 5 times to give the replica set time to elect a new primary, also checks against the
    valid_ips to verify that the primary is not outdated.
    """
    primary_ip = await fetch_primary(replica_set_hosts, ops_test, substrate, app_name)

    if substrate == "microk8s":
        unit_name = host_to_unit(primary_ip)

    # return None if primary is no longer in the replica set
    if substrate == "lxd" and primary_ip is not None and primary_ip not in replica_set_hosts:
        return None

    for unit in ops_test.model.applications[app_name].units:
        if substrate == "microk8s" and unit_name == unit.name:
            return unit
        if substrate == "lxd" and unit.public_address == str(primary_ip):
            return unit

    return None


@retry(
    retry=retry_if_result(lambda x: x is None),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=30),
)
async def replica_set_secondary(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    replica_set_hosts: list[str],
) -> JujuUnit | None:
    """Returns the primary of the replica set.

    Retrying 5 times to give the replica set time to elect a new primary, also checks against the
    valid_ips to verify that the primary is not outdated.
    """
    primary_ip = await fetch_primary(replica_set_hosts, ops_test, substrate, app_name)

    if substrate == "microk8s":
        unit_name = host_to_unit(primary_ip)

    # return None if primary is no longer in the replica set
    if substrate == "lxd" and primary_ip is not None and primary_ip not in replica_set_hosts:
        return None

    for unit in ops_test.model.applications[app_name].units:
        if substrate == "microk8s" and unit_name != unit.name:
            return unit
        if substrate == "lxd" and unit.public_address != str(primary_ip):
            return unit

    return None


def storage_type(ops_test: OpsTest, app: str) -> str | None:
    """Retrieves type of storage associated with an application.

    Note: this function exists as a temporary solution until this issue is resolved:
    https://github.com/juju/python-libjuju/issues/694
    """
    model_name = ops_test.model.info.name
    proc = subprocess.check_output(f"juju storage --model={model_name} --format=json".split())
    data = json.loads(proc.decode("utf-8"))

    if not data.get("storage", None):
        return None

    storage = data["storage"]

    for _, storage in storage.items():
        units = storage.get("attachments", {}).get("units", None)
        if units:
            app_name = one(units).split("/")[0]
        if app_name == app:
            if storage["status"]["current"] == "detached":
                continue
        return storage["kind"]

    return None


def storage_id(ops_test: OpsTest, unit_name: str) -> str | None:
    """Retrieves storage id associated with provided unit."""
    model_name = ops_test.model.info.name

    proc = subprocess.check_output(f"juju storage --model={model_name} --format json".split())
    data = json.loads(proc.decode("utf-8"))

    if not data.get("storage", None):
        logger.info(f"Storage {data=}")
        return None

    storage = data["storage"]

    for storage_id, storage in storage.items():
        units = storage.get("attachments", {}).get("units", None)
        if units:
            unit = one(units)
        if unit_name == unit:
            return storage_id

    logger.info(f"Storage {data=}")
    return None


async def reused_storage(
    ops_test: OpsTest, substrate: Substrate, unit_name: str, removal_time: float
) -> bool:
    """Returns True if storage provided to mongod has been reused.

    MongoDB startup message indicates storage reuse:
        If member transitions to STARTUP2 from STARTUP then it is syncing/getting data from
        primary.
        If member transitions to STARTUP2 from REMOVED then it is reusing the storage we
        provided.
    """
    match substrate:
        case "lxd":
            base_command = f"ssh {unit_name} sudo"
        case "microk8s":
            base_command = f"ssh --container mongod {unit_name}"

    cat_cmd = f"{base_command} cat {mongodb_log_path(substrate)}"
    return_code, output, _ = await ops_test.juju(*cat_cmd.split())

    if return_code != 0:
        raise ProcessError(
            f"Expected cat command {cat_cmd} to succeed instead it failed: {return_code}"
        )

    for line in output.splitlines():
        if not len(line):
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            logger.error(f"JSON decode error: {line}")
            continue

        # "attr" is needed and stores the state information and changes of mongodb
        if "attr" not in item:
            continue

        # Compute reuse time
        re_use_time = convert_time(item["t"]["$date"])

        # Get newstate and oldstate if present
        newstate = item["attr"].get("newState", "")
        oldstate = item["attr"].get("oldState", "")

        if newstate == "STARTUP2" and oldstate == "REMOVED" and re_use_time > removal_time:
            return True

    return False


def convert_time(time_as_str: str) -> float:
    """Converts a string time representation to an integer time representation, in UTC."""
    # parse time representation, provided in this format: 'YYYY-MM-DDTHH:MM:SS.MMM+00:00'
    d = datetime.strptime(time_as_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    return d.timestamp()


async def scale_application(
    ops_test: OpsTest,
    substrate: Substrate,
    application_name: str,
    count: int,
    wait: bool = True,
    raise_on_blocked: bool = True,
    timeout: int = TIMEOUT,
) -> None:
    """Scale a given application to the desired unit count.

    Args:
        ops_test: The ops test framework
        application_name: The name of the application
        count: The number of units to add/remove
        wait: Boolean indicating whether to wait until units
            reach desired count
        raise_on_blocked: Should the wait raise on blocked?
    """
    current_count = len(ops_test.model.applications[application_name].units)
    desired_count = count + current_count

    if count == 0:
        return

    if substrate == "microk8s":
        await ops_test.model.applications[application_name].scale(scale_change=count)

    else:
        if count > 0:
            logger.info(f"Scaling up by {count} units")
            await ops_test.model.applications[application_name].add_units(count)
        else:
            logger.info(f"Scaling down by {abs(count)} units")
            # find leader unit
            leader_unit = await find_unit(ops_test, leader=True)
            units_to_remove = []
            for unit in ops_test.model.applications[application_name].units:
                if unit.name == leader_unit.name:
                    continue
                if len(units_to_remove) < abs(count):
                    units_to_remove.append(unit.name)
            logger.info(f"Units to remove {units_to_remove}")
            await ops_test.model.applications[application_name].destroy_units(*units_to_remove)

    if desired_count > 0 and wait:
        logger.info("Waiting for idle")
        async with ops_test.fast_forward("1m"):
            # TODO: remove raise_on_error when we move to juju 3.5 (DPE-4996)
            await ops_test.model.wait_for_idle(
                apps=[application_name],
                status="active",
                timeout=timeout,
                wait_for_exact_units=desired_count,
                raise_on_error=False,
                raise_on_blocked=raise_on_blocked,
            )

        assert len(ops_test.model.applications[application_name].units) == desired_count


async def fetch_replica_set_members(
    ops_test: OpsTest, substrate: Substrate, app_name: str
) -> list[str]:
    """Fetches the hosts listed as replica set members in the MongoDB replica set configuration.

    Args:
        ops_test: reference to deployment.
    """
    # connect to replica set uri
    # get ips from MongoDB replica set configuration
    with await get_direct_mongo_client(ops_test, substrate, app_name) as client:
        data = client.admin.command("replSetGetConfig")

    return [member["host"].split(":")[0] for member in data["config"]["members"]]


async def verify_writes(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
) -> int:
    # verify that no writes to the db were missed
    total_expected_writes = await stop_continous_writes(
        ops_test, client_app_name=CONTINUOUS_WRITE_APPLICATION
    )

    hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary_unit = await replica_set_primary(
        ops_test,
        substrate,
        app_name,
        hosts,
    )

    assert primary_unit, "No primary unit"

    actual_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=primary_unit)

    assert total_expected_writes == actual_writes

    # Return it in case we need it later
    return total_expected_writes


async def kubectl_delete(ops_test: OpsTest, unit: JujuUnit, wait: bool = True) -> None:
    """Delete the underlying pod for a unit."""
    kubectl_cmd = (
        "microk8s",
        "kubectl",
        "delete",
        "pod",
        f"--wait={wait}",
        f"-n{ops_test.model_name}",
        unit.name.replace("/", "-"),
    )
    ret_code, _, _ = await ops_test.run(*kubectl_cmd)
    assert ret_code == 0, "Unit failed to delete"


RELEASES = {
    "focal": {"release_name": "Focal Fossa", "version": 20.04, "LTS": True},
    "jammy": {"release_name": "Jammy Jelly", "version": 22.04, "LTS": False},
}


async def insert_release_to_cluster(
    ops_test: OpsTest, substrate: Substrate, app_name: str, release: str = "focal"
) -> None:
    """Inserts the Focal Fossa data into the MongoDB cluster via primary replica."""
    app_name = await get_app_name(ops_test)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary = await replica_set_primary(ops_test, substrate, app_name, ip_addresses)
    primary_ip = await get_address_of_unit(
        ops_test, substrate, get_unit_id(primary.name), app_name=app_name
    )

    password = await get_password(ops_test, OPERATOR_USERNAME, app_name=app_name)
    client = MongoClient(unit_uri(primary_ip, password, app_name), directConnection=True)
    db = client[DEFAULT_DATABASE_NAME]
    test_collection = db[DEFAULT_REPLICATION_COLL_NAME]
    test_collection.insert_one(RELEASES[release])
    client.close()


async def retrieve_entries(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    db_name: str,
    collection_name: str,
    query_field: str,
):
    """Retries entries from a specified collection within a specified database."""
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary = await replica_set_primary(ops_test, substrate, app_name, ip_addresses)
    primary_ip = await get_address_of_unit(
        ops_test, substrate, get_unit_id(primary.name), app_name=app_name
    )

    password = await get_password(ops_test, OPERATOR_USERNAME, app_name=app_name)
    client = MongoClient(unit_uri(primary_ip, password, app_name), directConnection=True)

    db = client[db_name]
    test_collection = db[collection_name]

    # read all entries from original cluster
    cursor = test_collection.find({})
    cluster_entries = set()
    for document in cursor:
        cluster_entries.add(document[query_field])

    client.close()
    return cluster_entries


async def kill_unit_process(
    ops_test: OpsTest, substrate: Substrate, unit_name: str, kill_code: str, app_name=None
):
    """Kills the DB process on the unit according to the provided kill code."""
    # killing the only replica can be disastrous
    app_name = app_name or await get_app_name(ops_test)

    if substrate == "lxd":
        kill_cmd = f"exec --unit {unit_name} -- pkill --signal {kill_code} -f {VM_DB_PROCESS}"
    else:
        kill_cmd = f"ssh --container mongod {unit_name} pkill --signal {kill_code} {K8S_DB_PROCESS}"

    return_code, _, _ = await ops_test.juju(*kill_cmd.split())

    if return_code != 0:
        raise ProcessError(
            f"Expected kill command {kill_cmd} to succeed instead it failed: {return_code}"
        )


async def db_step_down(
    ops_test: OpsTest, substrate: Substrate, primary_name: str, sigterm_time: float, app_name: str
):
    # loop through all units that aren't the old primary
    app_name = await get_app_name(ops_test)
    log_path = mongodb_log_path(substrate)

    if substrate == "lxd":
        ls_command_template = "ssh {unit_name} sudo ls {log_path}"
        cat_command_template = "ssh {unit_name} sudo cat {log_path}"
    else:
        ls_command_template = "ssh  --container mongod {unit_name} ls {log_path}"
        cat_command_template = "ssh  --container mongod {unit_name} cat {log_path}"

    for unit in ops_test.model.applications[app_name].units:
        if unit.name == primary_name:
            continue
        # verify log file exists on this machine
        search_file = ls_command_template.format(unit_name=unit.name, log_path=log_path)
        return_code, _, _ = await ops_test.juju(*search_file.split())
        if return_code == 2:
            logger.info(f"Missing file {log_path}")
            continue

        # these log files can get quite large. According to the Juju team the 'run' command
        # cannot be used for more than 16MB of data so it is best to use juju ssh or juju scp.
        cat_file = cat_command_template.format(unit_name=unit.name, log_path=log_path)
        _, stdout, _ = await ops_test.juju(*cat_file.split())

        for line in stdout.splitlines():
            if not len(line):
                continue

            item = json.loads(line)

            step_down_time = convert_time(item["t"]["$date"])
            if (
                "Starting an election due to step up request" in line
                and step_down_time >= sigterm_time
            ):
                return True
            if (
                "Starting an election due to step up request" in line
                and step_down_time < sigterm_time
            ):
                logger.warning(f"Step down: {step_down_time} < {sigterm_time}")

    return False


async def update_restart_delay(
    ops_test: OpsTest, substrate: Substrate, unit: JujuUnit, delay: int, tmp_path: Path
):
    """Updates the restart delay in the DB service file.

    When the DB service fails it will now wait for `delay` number of seconds.
    """
    if substrate == "microk8s":
        modify_pebble_restart_delay(
            ops_test,
            unit.name,
            "tests/integration/helpers/manifests/extend_pebble_restart_delay.yml",
            ensure_replan=True,
        )
        return
    tmp_service_path = tmp_path / "tmp.service"
    # load the service file from the unit and update it with the new delay
    await unit.scp_from(source=MONGOD_SERVICE_DEFAULT_PATH, destination=tmp_service_path)
    with open(tmp_service_path) as mongodb_service_file:
        mongodb_service = mongodb_service_file.readlines()

    for index, line in enumerate(mongodb_service):
        if "RestartSec" in line:
            mongodb_service[index] = f"RestartSec={delay}s\n"

    with open(tmp_service_path, "w") as service_file:
        service_file.writelines(mongodb_service)

    # upload the changed file back to the unit, we cannot scp this file
    # directly to MONGOD_SERVICE_DEFAULT_PATH since this directory has
    # strict permissions, instead we scp it elsewhere and then move it to
    # MONGOD_SERVICE_DEFAULT_PATH.
    await unit.scp_to(source=tmp_service_path, destination="mongod.service")
    mv_cmd = f"exec --unit {unit.name} mv /home/ubuntu/mongod.service {MONGOD_SERVICE_DEFAULT_PATH}"
    return_code, _, _ = await ops_test.juju(*mv_cmd.split())
    if return_code != 0:
        raise ProcessError(f"Command: {mv_cmd} failed on unit: {unit.name}.")

    # reload the daemon for systemd otherwise changes are not saved
    reload_cmd = f"exec --unit {unit.name} systemctl daemon-reload"
    return_code, _, _ = await ops_test.juju(*reload_cmd.split())
    if return_code != 0:
        raise ProcessError(f"Command: {reload_cmd} failed on unit: {unit.name}.")


def modify_pebble_restart_delay(
    ops_test: OpsTest,
    unit_name: str,
    pebble_plan_path: str,
    ensure_replan: bool = False,
) -> None:
    """Modify the pebble restart delay of the underlying process.

    Args:
        ops_test: The ops test framework
        unit_name: The name of unit to extend the pebble restart delay for
        pebble_plan_path: Path to the file with the modified pebble plan
        ensure_replan: Whether to check that the replan command succeeded
    """
    kubernetes.config.load_kube_config()
    client = kubernetes.client.api.core_v1_api.CoreV1Api()

    pod_name = unit_name.replace("/", "-")
    container_name = "mongod"
    service_name = "mongod"
    now = datetime.now().isoformat()

    copy_file_into_pod(
        client,
        ops_test.model.info.name,
        pod_name,
        container_name,
        f"/tmp/pebble_plan_{now}.yml",
        pebble_plan_path,
    )

    add_to_pebble_layer_commands = (
        f"/charm/bin/pebble add --combine {service_name} /tmp/pebble_plan_{now}.yml"
    )
    response = kubernetes.stream.stream(
        client.connect_get_namespaced_pod_exec,
        pod_name,
        ops_test.model.info.name,
        container=container_name,
        command=add_to_pebble_layer_commands.split(),
        stdin=False,
        stdout=True,
        stderr=True,
        tty=False,
        _preload_content=False,
    )
    response.run_forever(timeout=5)
    assert (
        response.returncode == 0
    ), f"Failed to add to pebble layer, unit={unit_name}, container={container_name}, service={service_name}"

    for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3)):
        with attempt:
            replan_pebble_layer_commands = "/charm/bin/pebble replan"
            response = kubernetes.stream.stream(
                client.connect_get_namespaced_pod_exec,
                pod_name,
                ops_test.model.info.name,
                container=container_name,
                command=replan_pebble_layer_commands.split(),
                stdin=False,
                stdout=True,
                stderr=True,
                tty=False,
                _preload_content=False,
            )
            response.run_forever(timeout=60)
            if ensure_replan:
                assert (
                    response.returncode == 0
                ), f"Failed to replan pebble layer, unit={unit_name}, container={container_name}, service={service_name}"


def copy_file_into_pod(
    client: kubernetes.client.api.core_v1_api.CoreV1Api,
    namespace: str,
    pod_name: str,
    container_name: str,
    source_path: str,
    destination_path: str,
) -> None:
    """Copy file contents into pod.

    Args:
        client: The kubernetes CoreV1Api client
        namespace: The namespace of the pod to copy files to
        pod_name: The name of the pod to copy files to
        container_name: The name of the pod container to copy files to
        source_path: The path to which the file should be copied over
        destination_path: The path of the file which needs to be copied over
    """
    try:
        exec_command = ["tar", "xvf", "-", "-C", "/"]

        api_response = kubernetes.stream.stream(
            client.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            container=container_name,
            command=exec_command,
            stdin=True,
            stdout=True,
            stderr=True,
            tty=False,
            _preload_content=False,
        )

        with tempfile.TemporaryFile() as tar_buffer:
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                tar.add(destination_path, source_path)

            tar_buffer.seek(0)
            commands = []
            commands.append(tar_buffer.read())

            while api_response.is_open():
                api_response.update(timeout=1)

                if commands:
                    command = commands.pop(0)
                    api_response.write_stdin(command.decode())
                else:
                    break

            api_response.close()
    except kubernetes.client.rest.ApiException:
        assert False


async def all_db_processes_down(ops_test: OpsTest, substrate: Substrate, app_name: str) -> bool:
    """Verifies that all units of the charm do not have the DB process running."""
    if substrate == "lxd":
        search_db_template = "exec --unit {unit_name} pgrep -x mongod"
    else:
        search_db_template = "ssh --container mongod {unit_name} pgrep -x mongod"
    try:
        for attempt in Retrying(stop=stop_after_attempt(60), wait=wait_fixed(3)):
            with attempt:
                for unit in ops_test.model.applications[app_name].units:
                    search_db_process = search_db_template.format(unit_name=unit.name)
                    _, processes, _ = await ops_test.juju(*search_db_process.split())
                    # splitting processes by "\n" results in one or more empty lines, hence we
                    # need to process these lines accordingly.
                    processes = [proc for proc in processes.split("\n") if len(proc) > 0]
                    if len(processes) > 0:
                        raise ProcessRunningError
    except RetryError:
        return False

    return True


@retry(stop=stop_after_attempt(8), wait=wait_fixed(15))
async def verify_replica_set_configuration(
    ops_test: OpsTest, substrate: Substrate, app_name: str
) -> None:
    """Verifies presence of primary, replica set members, and number of primaries."""
    hosts = [
        await get_mongodb_hostname_for_unit(ops_test, substrate, unit.name)
        for unit in ops_test.model.applications[app_name].units
    ]

    # verify presence of primary
    new_primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=hosts
    )
    assert new_primary.name, "primary not elected."

    # verify all units are running under the same replset
    member_ips = await fetch_replica_set_members(ops_test, substrate, app_name=app_name)
    assert set(member_ips) == set(hosts), "all members not running under the same replset"

    password = await get_password(ops_test, OPERATOR_USERNAME, app_name=app_name)

    # verify there is only one primary
    assert (
        await count_primaries(ops_test, substrate, password, app_name=app_name) == 1
    ), "there are more than one primary in the replica set."


def is_machine_reachable_from(origin_machine: str, target_machine: str) -> bool:
    """Test network reachability between hosts.

    Args:
        origin_machine: hostname of the machine to test connection from
        target_machine: hostname of the machine to test connection to
    """
    try:
        subprocess.check_call(f"lxc exec {origin_machine} -- ping -c 3 {target_machine}".split())
        return True
    except subprocess.CalledProcessError:
        return False


async def get_controller_machine(ops_test: OpsTest) -> str:
    """Return controller machine hostname.

    Args:
        ops_test: The ops test framework instance
    Returns:
        Controller hostname (str)
    """
    _, raw_controller, _ = await ops_test.juju("show-controller")

    controller = yaml.safe_load(raw_controller.strip())

    return [
        machine.get("instance-id")
        for machine in controller[ops_test.controller_name]["controller-machines"].values()
    ][0]
