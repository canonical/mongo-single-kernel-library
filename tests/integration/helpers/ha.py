#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""High availability helpers."""

import os
import string
import subprocess
import tempfile
from logging import getLogger

from juju.unit import Unit as JujuUnit
from pytest_operator.plugin import OpsTest
from tenacity import retry, retry_if_result, stop_after_attempt, wait_exponential, wait_fixed

from ..helpers.common import (
    execute_on_mongod,
    generate_mongodb_client,
    get_password,
    instance_ip,
)
from ..helpers.types import Substrate

logger = getLogger(__name__)


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


async def fetch_primary(
    replica_set_hosts: list[str],
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
) -> str | None:
    """Returns IP address of current replica set primary."""
    password = await get_password(ops_test, username="operator", app_name=app_name)

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

    return primary


@retry(
    retry=retry_if_result(lambda x: x is None),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=30),
)
async def replica_set_primary(
    replica_set_hosts: list[str],
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
) -> JujuUnit | None:
    """Returns the primary of the replica set.

    Retrying 5 times to give the replica set time to elect a new primary, also checks against the
    valid_ips to verify that the primary is not outdated.
    """
    primary_ip = await fetch_primary(replica_set_hosts, ops_test, substrate, app_name)

    # return None if primary is no longer in the replica set
    if primary_ip is not None and primary_ip not in replica_set_hosts:
        return None

    for unit in ops_test.model.applications[app_name].units:
        if unit.public_address == str(primary_ip):
            return unit

    return None
