#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""High availability helpers."""

import base64
import json
import os
import shlex
import string
import subprocess  # nosec: B404
import tempfile
import time
from datetime import datetime
from logging import getLogger

import jubilant
import urllib3
import yaml
from jubilant.statustypes import Status
from kubernetes import client, config, stream
from kubernetes.client.exceptions import ApiException
from pymongo import MongoClient
from tenacity import RetryError, Retrying, retry, stop_after_attempt, stop_after_delay, wait_fixed

from tests.integration.helpers.common import ProcessError, mongodb_log_path
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    DEFAULT_DATABASE_NAME,
    DEFAULT_REPLICATION_COLL_NAME,
    RELEASES,
)
from tests.integration.helpers.continuous_writes_helpers import replica_set_primary
from tests.integration.helpers.ha import ProcessRunningError
from tests.integration.helpers.jubilant_common import (
    count_primaries,
    execute_on_mongod,
    find_leader,
    get_app_name_from_unit,
    get_ip_from_unit,
    get_ips_for_app,
    get_mongodb_hostnames_for_app,
    get_password,
    read_remote_file,
    replica_set_uri,
    run_command_on_server,
    unit_uri,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)

MONGOD_SERVICE_DEFAULT_PATH = "/etc/systemd/system/snap.charmed-mongodb.mongod.service"
VM_RESTART_DELAY_DEFAULT = 20
K8S_RESTART_DELAY_DEFAULT = 5
RESTART_DELAY_PATCHED = 120

# Budget for a whole `juju ssh` round trip (CLI start-up, controller API, SSH handshake,
# `sudo -i` on VM); the remote commands themselves are instantaneous, so this is a hang guard.
SSH_COMMAND_TIMEOUT = 60


EXTEND_PEBBLE_RESTART_DELAY_YAML = """services:
  mongod:
    override: merge
    backoff-delay: {delay}s
    backoff-limit: {delay}s
"""

RESTORE_PEBBLE_RESTART_DELAY_YAML = """services:
  mongod:
    override: merge
    backoff-delay: 500ms
    backoff-limit: 30s
"""

# Cut the network without changing the unit's IP by dropping packets inside the container:
# masking the NIC (the ip_change path) drops the DHCP lease, and a bandwidth throttle (what
# this used to do) still lets Sentinel PING/PONG trickle through, so +odown never reaches
# quorum and no failover starts. Loopback stays open for the charm's own health checks;
# `lxc exec` rides the LXD socket, so cut and restore work while the container is isolated.
NETWORK_CUT_RULES = (
    "INPUT ! --in-interface lo --jump DROP",
    "OUTPUT ! --out-interface lo --jump DROP",
)


def storage_type(juju: jubilant.Juju, app_name: str, storage_name: str) -> str | None:
    """Retrieves type of storage associated with an application."""
    storages = juju.status().storage

    for storage in storages.filesystems.values():
        unit_name = next(iter(storage.attachments.units))
        if get_app_name_from_unit(unit_name) == app_name:
            # We don't want to consider the detached storages
            if storage.status.current == "detached":
                continue
            # We don't want to consider the storages that don't match the storage name.
            if not storage.storage.startswith(f"{storage_name}"):
                continue
            return storage.pool

    return None


def storage_id(juju: jubilant.Juju, unit_name: str, storage_name: str) -> str | None:
    """Retrieves storage id associated with provided unit."""
    for storage_info in juju.status().storage.filesystems.values():
        storage_unit_name = next(iter(storage_info.attachments.units))
        if unit_name != storage_unit_name:
            continue
        if storage_info.storage.startswith(f"{storage_name}"):
            return storage_info.storage
    return None


def lxd_cut_network_from_unit_with_ip_change(machine_name: str) -> None:
    """Cut network from a lxc container in a way the changes the IP."""
    # apply a mask (device type `none`)
    cut_network_command = f"lxc config device add {machine_name} eth0 none"
    subprocess.check_call(shlex.split(cut_network_command))  # nosec: B603

    time.sleep(5)


def _lxd_delete_iptables_rule(machine_name: str, rule: str) -> bool:
    """Delete an iptables rule inside an lxc container, reporting whether it was there."""
    command = f"lxc exec {machine_name} -- iptables --delete {rule}"
    returncode = subprocess.call(  # nosec: B603
        shlex.split(command), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return returncode == 0


def lxd_cut_network_from_unit_without_ip_change(machine_name: str) -> None:
    """Cut network from a lxc container (without causing the change of the unit IP address)."""
    for rule in NETWORK_CUT_RULES:
        # drop a leftover copy first so re-cutting cannot stack a duplicate rule
        _lxd_delete_iptables_rule(machine_name, rule)
        subprocess.check_call(shlex.split(f"lxc exec {machine_name} -- iptables --insert {rule}"))  # nosec: B603


def lxd_restore_network_to_unit_without_ip_change(machine_name: str) -> None:
    """Restore the network of a lxc container that was cut without an IP address change."""
    for rule in NETWORK_CUT_RULES:
        # tolerate a missing rule so restoring twice is a no-op
        if not _lxd_delete_iptables_rule(machine_name, rule):
            logger.warning("iptables rule %r was not present on %s", rule, machine_name)


def k8s_cut_network_from_unit_without_ip_change(model_name: str, machine_name: str) -> None:
    """Cut network from a k8s pod without causing the change of the unit IP address."""
    # Apply a NetworkChaos file to use chaos-mesh to simulate a network cut.
    with tempfile.NamedTemporaryFile(dir=".") as temp_file:
        # Generates a manifest for chaosmesh to simulate network failure for a pod
        with open(
            "tests/integration/helpers/manifests/chaos_network_loss.yml"
        ) as chaos_network_loss_file:
            logger.info(f"Calling network loss on ns={model_name} and pod={machine_name}")
            template = string.Template(chaos_network_loss_file.read())
            chaos_network_loss = template.substitute(
                namespace=model_name,
                pod=machine_name,
            )

            temp_file.write(str.encode(chaos_network_loss))
            temp_file.flush()

        # Apply the generated manifest, chaosmesh would then make the pod inaccessible.
        # The chaos-mesh admission webhook (mnetworkchaos.kb.io) can take a while to
        # start serving after the controller-manager is installed; until it does the
        # apply fails with a transient "connection refused" calling the webhook. Retry
        # for a bounded window so the webhook has time to come up.
        env = os.environ
        env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")
        command_result = None
        for attempt in Retrying(stop=stop_after_delay(120), wait=wait_fixed(5), reraise=True):
            with attempt:
                try:
                    command_result = subprocess.check_output(  # nosec: B603
                        shlex.split(f"sudo k8s kubectl apply -f {temp_file.name}"),
                        env=env,
                        stderr=subprocess.STDOUT,
                    )
                except subprocess.CalledProcessError as err:
                    logger.error(
                        f"Failed to apply network isolation: [{err.returncode}] {err.stderr=}, {err.stdout=}"
                    )
                    raise
        logger.info("Result of isolating unit from cluster is '%s'", command_result)

        # `kubectl apply` only means the API server accepted the NetworkChaos; chaos-mesh
        # programs the netem rule asynchronously (NetworkChaos -> PodNetworkChaos ->
        # chaos-daemon), which can take longer than the reachability probe's pod start-up.
        # Wait until chaos-mesh reports the rule injected before returning, so the "cut" is
        # synchronous like the LXD iptables variant.
        _k8s_wait_network_chaos_injected(model_name)


def _k8s_wait_network_chaos_injected(namespace: str) -> None:
    """Block until the `network-loss-primary` NetworkChaos is selected and fully injected.

    Chaos-mesh only flips a record to `Injected` after the daemon applied the tc rule
    (PodNetworkChaos `observedGeneration` catches up), so `AllInjected=True` is the real
    "packets are being dropped" signal. `Selected=True` is required as well: before any pod
    is selected the record loop is empty and `AllInjected` is vacuously True.
    """
    for attempt in Retrying(stop=stop_after_delay(120), wait=wait_fixed(2), reraise=True):
        with attempt:
            output = subprocess.check_output(  # nosec: B603
                shlex.split(
                    f"sudo k8s kubectl -n {namespace} get networkchaos network-loss-primary -o json"
                ),
                env=os.environ,
                stderr=subprocess.STDOUT,
            )
            conditions = {
                cond["type"]: cond["status"]
                for cond in json.loads(output).get("status", {}).get("conditions", [])
            }
            if conditions.get("Selected") != "True" or conditions.get("AllInjected") != "True":
                raise ValueError(f"network chaos not injected yet: {conditions}")
            logger.info("Network chaos injected: %s", conditions)


def cut_network_from_unit(
    substrate: Substrate, model_name: str, machine_name: str, ip_change: bool = False
) -> None:
    """Cut network from a unit.

    Args:
        substrate: The substrate the test is running on
        model_name: The juju model name (only applicable for k8s)
        machine_name: lxc container hostname or k8s pod name
        ip_change: Whether to change the IP address of the unit on the network cut (VM only)
    """
    if substrate == Substrate.lxd:
        if ip_change:
            lxd_cut_network_from_unit_with_ip_change(machine_name)
        else:
            lxd_cut_network_from_unit_without_ip_change(machine_name)
    else:
        k8s_cut_network_from_unit_without_ip_change(model_name, machine_name)


def restore_network_to_unit(
    substrate: Substrate, model_name: str, machine_name: str, ip_change: bool = False
) -> None:
    """Restore network from a unit.

    Args:
        substrate: The substrate the test is running on
        model_name: The juju model name (only applicable for k8s)
        machine_name: lxc container hostname or k8s pod name
        ip_change: Whether the network cut changed the IP address of the unit (VM only)
    """
    if substrate == Substrate.lxd:
        if ip_change:
            # remove mask from eth0
            restore_network_command = f"lxc config device remove {machine_name} eth0"
            subprocess.check_call(shlex.split(restore_network_command))  # nosec: B603
            return
        lxd_restore_network_to_unit_without_ip_change(machine_name)
    else:
        env = os.environ
        env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")
        subprocess.check_output(  # nosec: B603
            shlex.split(
                f"sudo k8s kubectl -n {model_name} delete networkchaos network-loss-primary"
            ),
            env=env,
        )


def k8s_deploy_chaos_mesh(namespace: str) -> None:
    """Deploy chaos mesh to the provided namespace.

    Chaos mesh can them be used by the tests to simulate a variety of failures.

    Args:
        namespace: The namespace to deploy chaos mesh to
    """
    env = os.environ
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")

    subprocess.check_output(  # nosec: B603
        shlex.split(f"tests/integration/helpers/scripts/deploy_chaos_mesh.sh {namespace}"),
        env=env,
    )


def k8s_destroy_chaos_mesh(namespace: str) -> None:
    """Destroy chaos mesh on a provided namespace.

    Cleans up the test K8S from test related dependencies.

    Args:
        namespace: The namespace to deploy chaos mesh to
    """
    env = os.environ
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")

    subprocess.check_output(  # nosec: B603
        shlex.split(f"tests/integration/helpers/scripts/destroy_chaos_mesh.sh {namespace}"),
        env=env,
    )


def is_unit_reachable_k8s(namespace: str, source_pod_name: str, to_host: str) -> bool:
    """Test network reachability to a unit in k8s.

    Creates a temporary pod with the same labels as the source pod and
    trying to ping the destination IP.
    """
    # ---------------------------------------------------------
    # 1. Setup Client and Bypass SSL (for local/testing clusters)
    # ---------------------------------------------------------
    config.load_kube_config()

    configuration = client.Configuration.get_default_copy()
    configuration.verify_ssl = False
    client.Configuration.set_default(configuration)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    v1 = client.CoreV1Api()

    # ---------------------------------------------------------
    # 2. Fetch Labels from the Source Pod
    # ---------------------------------------------------------
    try:
        source_pod = v1.read_namespaced_pod(name=source_pod_name, namespace=namespace)
        source_labels = source_pod.metadata.labels or {}
        logger.info(f"Fetched labels from {source_pod_name}: {source_labels}")
    except ApiException as e:
        logger.error(f"Failed to read source pod {source_pod_name}: {e}")
        return False

    # ---------------------------------------------------------
    # 3. Define the Temporary Test Pod
    # ---------------------------------------------------------
    temp_pod_name = f"netshoot-test-{int(time.time())}"

    pod_manifest = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=temp_pod_name,
            namespace=namespace,
            labels=source_labels,  # <--- Injecting the source pod's labels here
        ),
        spec=client.V1PodSpec(
            restart_policy="Never",
            containers=[
                client.V1Container(
                    name="netshoot",
                    image="nicolaka/netshoot",
                    # Ping five times (-c 5), wait up to 2 seconds for a response (-W 2)
                    command=["ping", "-c", "5", "-W", "2", to_host],
                )
            ],
        ),
    )

    # ---------------------------------------------------------
    # 4. Execute and Wait for Results
    # ---------------------------------------------------------
    try:
        logger.info(f"Creating test pod '{temp_pod_name}' to ping {to_host}...")
        v1.create_namespaced_pod(namespace=namespace, body=pod_manifest)

        # Poll the pod status until it completes
        phase = None
        for attempt in Retrying(stop=stop_after_attempt(30), wait=wait_fixed(2), reraise=True):
            with attempt:
                pod_status = v1.read_namespaced_pod(name=temp_pod_name, namespace=namespace)
                phase = pod_status.status.phase

                if phase not in ["Succeeded", "Failed"]:
                    logger.info(
                        f"Pod '{temp_pod_name}' is in phase '{phase}'. Waiting for completion..."
                    )
                    raise ValueError("Pod not completed yet")

        # Optional: Fetch the actual ping output logs for debugging
        logs = v1.read_namespaced_pod_log(name=temp_pod_name, namespace=namespace)
        logger.info(f"Ping Output:\n{logs.strip()}")

        # If phase is Succeeded, the ping command returned exit code 0
        is_reachable = phase == "Succeeded"

        if is_reachable:
            logger.info(f"Success: {to_host} is reachable from {source_pod_name}.")
        else:
            logger.error(f"Failure: {to_host} is NOT reachable from {source_pod_name}.")

        return is_reachable

    except ApiException as e:
        logger.error(f"Exception during pod creation/execution: {e}")
        return False

    # ---------------------------------------------------------
    # 5. Clean Up (Always runs, even if errors occur above)
    # ---------------------------------------------------------
    finally:
        logger.info(f"Cleaning up pod '{temp_pod_name}'...")
        try:
            v1.delete_namespaced_pod(name=temp_pod_name, namespace=namespace)
        except ApiException as e:
            logger.error(f"Failed to delete temporary pod {temp_pod_name}: {e}")


def is_unit_reachable_lxd(from_host: str, to_host: str, number_of_retries: int = 10) -> bool:
    """Test network reachability between LXD hosts."""
    try:
        for attempt in Retrying(stop=stop_after_attempt(number_of_retries), wait=wait_fixed(10)):
            with attempt:
                ping = subprocess.call(  # nosec: B603
                    shlex.split(f"lxc exec {from_host} -- ping -c 5 -W 2 {to_host}"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if ping == 0:
                    return True
                raise ValueError
    except RetryError:
        return False
    return False


def is_unit_reachable(
    juju: jubilant.Juju,
    from_host: str,
    to_host: str,
    substrate: Substrate,
    number_of_retries: int = 10,
) -> bool:
    """Test network reachability to a unit based on the substrate."""
    assert juju.model, "Juju client must be connected to a model before checking unit reachability"
    match substrate:
        case Substrate.k8s:
            return is_unit_reachable_k8s(juju.model, from_host, to_host)
        case Substrate.lxd:
            return is_unit_reachable_lxd(from_host, to_host, number_of_retries=number_of_retries)


def get_sans_from_certificate(certificate_path: str) -> dict[str, set[str]]:
    """Get the SANs for a unit's cert."""
    sans_ip: set[str] = set()
    sans_dns: set[str] = set()
    if not (
        san_lines := subprocess.run(  # nosec: B603
            shlex.split(f"openssl x509 -ext subjectAltName -noout -in  {certificate_path}"),
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    ):
        return {"sans_ip": sans_ip, "sans_dns": sans_dns}

    for line in san_lines:
        for sans in line.split(", "):
            san_type, san_value = sans.split(":")

            if san_type.strip() == "DNS":
                sans_dns.add(san_value)
            if san_type.strip() == "IP Address":
                sans_ip.add(san_value)

    return {"sans_ip": sans_ip, "sans_dns": sans_dns}


def lxd_get_controller_hostname(juju: jubilant.Juju) -> str:
    """Return controller machine hostname."""
    assert juju.model
    raw_model = juju.cli("show-model", juju.model, include_model=False)
    raw_controller = juju.cli("show-controller", include_model=False)

    model_details = yaml.safe_load(raw_model)
    controller_details = yaml.safe_load(raw_controller)
    controller_name = model_details[juju.model]["controller-name"]

    return [
        machine.get("instance-id")
        for machine in controller_details[controller_name]["controller-machines"].values()
    ][0]


def send_process_control_signal(
    juju: jubilant.Juju,
    substrate: Substrate,
    unit_name: str,
    signal: str,
    db_process: str,
    container: str = "mongod",
) -> None:
    """Send control signal to a database process running on a Juju unit.

    Args:
        juju: the juju jubilant object.
        substrate: the substrate the test is running on
        unit_name: the Juju unit running the process
        model_full_name: the Juju model for the unit
        signal: the signal to issue, e.g `SIGKILL`
        db_process: the path to the database process binary
        container: the container to execute the commands on.
    """
    run_command_on_server(
        juju, substrate, unit_name, f"pkill --signal {signal} {db_process}", container
    )
    logger.info(f"Signal {signal} sent to database process on unit {unit_name}.")
    time.sleep(3)  # give some time for the signal to take effect before the test continues


def lxd_patch_restart_delay(juju: jubilant.Juju, unit_name: str, delay: int | None = None) -> None:
    """Update the restart delay in the snap's systemd service file."""
    delay = delay or VM_RESTART_DELAY_DEFAULT
    juju.exec(
        command=f"sed -i 's/^RestartSec=.*/RestartSec={delay}s/' {MONGOD_SERVICE_DEFAULT_PATH}",
        unit=unit_name,
    )

    # reload the daemon for systemd to reflect changes
    juju.exec(command="sudo systemctl daemon-reload", unit=unit_name)


def _pod_exec(
    kube_client: client.api.core_v1_api.CoreV1Api,
    namespace: str,
    pod_name: str,
    container_name: str,
    command: list[str],
    timeout: int = 30,
) -> tuple[int | None, str]:
    """Run a command in a pod container and return (returncode, combined output).

    A returncode of None means the command did not complete within the timeout.
    """
    response = stream.stream(
        kube_client.connect_get_namespaced_pod_exec,
        pod_name,
        namespace,
        container=container_name,
        command=command,
        stdin=False,
        stdout=True,
        stderr=True,
        tty=False,
        _preload_content=False,
    )
    response.run_forever(timeout=timeout)
    return response.returncode, response.read_all()


def pebble_patch_restart_delay(
    juju: jubilant.Juju,
    unit_name: str,
    delay: int | None = None,
    ensure_replan: bool = False,
    container: str = "mongod",
) -> None:
    """Modify the pebble restart delay of the underlying process.

    Args:
        juju: An instance of Jubilant's Juju class on which to run Juju commands.
        unit_name: The name of unit to extend the pebble restart delay for.
        delay: The new restart delay to apply.
        ensure_replan: Whether to check that the replan command succeeded.
        container: the container to execute the commands on.
    """
    pebble_file_content = (
        EXTEND_PEBBLE_RESTART_DELAY_YAML.format(delay=delay)
        if delay
        else RESTORE_PEBBLE_RESTART_DELAY_YAML
    )
    config.load_kube_config()
    kube_client = client.api.core_v1_api.CoreV1Api()

    pod_name = unit_name.replace("/", "-")
    container_name = container
    service_name = container
    layer_path = f"/tmp/pebble_plan_{datetime.now().isoformat()}.yml"

    # A one-shot base64 write avoids the tar-over-stdin websocket dance, whose
    # close() raced tar's read and could leave a truncated layer file behind.
    encoded = base64.b64encode(pebble_file_content.encode()).decode()
    for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3), reraise=True):
        with attempt:
            returncode, output = _pod_exec(
                kube_client,
                juju.model,
                pod_name,
                container_name,
                ["sh", "-c", f"echo {encoded} | base64 -d > {layer_path}"],
            )
            assert returncode == 0, (
                f"Failed to write pebble layer file, unit={unit_name}, "
                f"container={container_name}, returncode={returncode}, output={output!r}"
            )

            returncode, output = _pod_exec(
                kube_client,
                juju.model,
                pod_name,
                container_name,
                ["/charm/bin/pebble", "add", "--combine", service_name, layer_path],
            )
            assert returncode == 0, (
                f"Failed to add to pebble layer, unit={unit_name}, "
                f"container={container_name}, service={service_name}, "
                f"returncode={returncode}, output={output!r}"
            )

    for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3), reraise=True):
        with attempt:
            returncode, output = _pod_exec(
                kube_client,
                juju.model,
                pod_name,
                container_name,
                ["/charm/bin/pebble", "replan"],
                timeout=60,
            )
            if ensure_replan:
                assert returncode == 0, (
                    f"Failed to replan pebble layer, unit={unit_name}, "
                    f"container={container_name}, service={service_name}, "
                    f"returncode={returncode}, output={output!r}"
                )


def patch_restart_delay(
    juju: jubilant.Juju,
    substrate: Substrate,
    unit_name: str,
    delay: int | None,
) -> None:
    """Update the restart delay for the database process based on the substrate."""
    match substrate:
        case Substrate.lxd:
            lxd_patch_restart_delay(juju, unit_name, delay)
        case Substrate.k8s:
            pebble_patch_restart_delay(juju, unit_name, delay=delay, ensure_replan=True)


def reboot_unit(juju: jubilant.Juju, unit_name: str, substrate: Substrate) -> None:
    """Reboot a unit."""
    if substrate == Substrate.lxd:
        juju.exec(command="sudo reboot", unit=unit_name)
    else:
        delete_pod(unit_name.replace("/", "-"), juju.model)


def delete_pod(pod_name: str, namespace: str = "testing") -> None:
    """Delete a pod from the cluster."""
    # Load the kubeconfig file from your local machine (~/.kube/config)
    # Note: If running this script INSIDE a pod, use config.load_incluster_config() instead.
    config.load_kube_config()

    configuration = client.Configuration.get_default_copy()
    configuration.verify_ssl = False
    client.Configuration.set_default(configuration)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # CoreV1Api contains the methods for core resources like Pods, Services, etc.
    v1 = client.CoreV1Api()

    try:
        # Call the API to delete the pod
        logger.info("Attempting to delete pod %s in namespace '%s'...", pod_name, namespace)
        v1.delete_namespaced_pod(name=pod_name, namespace=namespace)

        logger.info("Success! Pod deleted.")

    except ApiException as e:
        # Handle API errors (e.g., pod not found, unauthorized, etc.)
        if e.status == 404:
            logger.warning("Error: Pod '%s' not found in namespace '%s'.", pod_name, namespace)
        else:
            logger.error("Exception when calling CoreV1Api->delete_namespaced_pod: %s", e)
            raise


def instance_ip(juju: jubilant.Juju, instance: str) -> str:
    """Translate juju instance name to IP.

    Args:
        juju: The juju client
        instance: The name of the instance

    Returns:
        The (str) IP address of the instance
    """
    for machine in juju.status().machines.values():
        if machine.hostname == instance:
            return machine.ip_addresses[0]
    return ""


def host_to_unit(host: str | None) -> str | None:
    return "/".join(host.split(".")[0].rsplit("-", 1)) if host else None


@retry(stop=stop_after_attempt(60), wait=wait_fixed(15), reraise=True)
def wait_network_restore(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    hostname: str,
    old_ip: str,
    ip_change: bool = True,
    unit_count: int | None = None,
) -> None:
    """Wait until network is restored.

    Args:
        juju: Juju client
        substrate: The substrate the test is running on (VM or k8s)
        app_name: The name of the application
        hostname: The name of the instance
        old_ip: old registered IP address
        ip_change: Whether to check for IP change
        unit_count: The expected number of units for the application (optional)
    """
    if substrate == Substrate.lxd and ip_change:
        if instance_ip(juju, hostname) == old_ip:
            raise Exception("Network not restored, IP address has not changed yet.")
    else:
        # Wait for the network to be restored
        juju.wait(
            lambda status: are_apps_active_and_agents_idle(
                status, app_name, unit_count=unit_count, idle_period=30
            )
        )


def fetch_replica_set_members(
    juju: jubilant.Juju, substrate: Substrate, app_name: str
) -> list[str]:
    """Fetches the hosts listed as replica set members in the MongoDB replica set configuration.

    Args:
        ops_test: reference to deployment.
    """
    # connect to replica set uri
    # get ips from MongoDB replica set configuration
    password = get_password(
        juju=juju,
        app_name=app_name,
        username=CHARMED_OPERATOR_USERNAME,
    )
    _, leader_status = find_leader(juju, app_name)
    host = get_ip_from_unit(substrate, leader_status)

    # connect to mongod
    uri = unit_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=password,
        ip_address=host,
        replica_set=app_name,
    )
    with MongoClient(uri, directConnection=True) as client:
        data = client.admin.command("replSetGetConfig")

    return [member["host"].split(":")[0] for member in data["config"]["members"]]


@retry(stop=stop_after_attempt(8), wait=wait_fixed(15))
def verify_replica_set_configuration(
    juju: jubilant.Juju, substrate: Substrate, app_name: str
) -> None:
    """Verifies presence of primary, replica set members, and number of primaries."""
    hosts = get_mongodb_hostnames_for_app(juju, substrate, app_name)

    # verify presence of primary
    new_primary_name, _ = replica_set_primary(juju, substrate, app_name=app_name)
    assert new_primary_name, "primary not elected."

    # verify all units are running under the same replset
    member_hosts = fetch_replica_set_members(juju, substrate, app_name=app_name)
    assert set(member_hosts) == set(hosts), "all members not running under the same replset"

    # verify there is only one primary
    assert (
        count_primaries(juju, substrate, app_name=app_name) == 1
    ), "there are more than one primary in the replica set."


def convert_time(time_as_str: str) -> float:
    """Converts a string time representation to an integer time representation, in UTC."""
    # parse time representation, provided in this format: 'YYYY-MM-DDTHH:MM:SS.MMM+00:00'
    d = datetime.strptime(time_as_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    return d.timestamp()


def reused_storage(
    juju: jubilant.Juju, substrate: Substrate, unit_name: str, removal_time: float
) -> bool:
    """Returns True if storage provided to mongod has been reused.

    MongoDB startup message indicates storage reuse:
        If member transitions to STARTUP2 from STARTUP then it is syncing/getting data from
        primary.
        If member transitions to STARTUP2 from REMOVED then it is reusing the storage we
        provided.
    """
    try:
        data = read_remote_file(juju, substrate, unit_name, mongodb_log_path(substrate))
    except jubilant.CLIError:
        raise ProcessError(f"Failed to read file {mongodb_log_path(substrate)} on unit {unit_name}")

    for line in data.splitlines():
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


def insert_release_to_cluster(
    juju: jubilant.Juju, substrate: Substrate, app_name: str, release: str = "focal"
) -> None:
    """Inserts the Focal Fossa data into the MongoDB cluster via primary replica."""
    _, primary_status = replica_set_primary(juju, substrate, app_name)
    primary_ip = get_ip_from_unit(substrate, primary_status)

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)
    uri = unit_uri(CHARMED_OPERATOR_USERNAME, password, primary_ip, app_name, mongos=False)
    client = MongoClient(uri, directConnection=True)
    db = client[DEFAULT_DATABASE_NAME]
    test_collection = db[DEFAULT_REPLICATION_COLL_NAME]
    test_collection.insert_one(RELEASES[release])
    client.close()


def retrieve_entries(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    db_name: str,
    collection_name: str,
    query_field: str,
):
    """Retries entries from a specified collection within a specified database."""
    _, primary_status = replica_set_primary(juju, substrate, app_name)
    primary_ip = get_ip_from_unit(substrate, primary_status)

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)
    uri = unit_uri(CHARMED_OPERATOR_USERNAME, password, primary_ip, app_name, mongos=False)
    client = MongoClient(uri, directConnection=True)

    db = client[db_name]
    test_collection = db[collection_name]

    # read all entries from original cluster
    cursor = test_collection.find({})
    cluster_entries: set[dict[str, str | float | bool]] = set()
    for document in cursor:
        cluster_entries.add(document[query_field])

    client.close()
    return cluster_entries


def db_step_down(  # noqa: C901
    juju: jubilant.Juju,
    substrate: Substrate,
    sigterm_time: float,
    app_name: str,
) -> bool:
    """Checks that the DB has stepped down.

    We check that by checking the reason of the last election in the metrics.
    It can be stepUpRequest or stepUpRequestSkipDryRun.
    We then confirm that it happened after the SIGTERM time.
    """
    username = CHARMED_OPERATOR_USERNAME
    password = get_password(juju, app_name, username=username)
    hosts = get_ips_for_app(juju, substrate, app_name)
    uri = replica_set_uri(
        username=username, password=password, ip_addresses=list(hosts), replica_set=app_name
    )

    result = execute_on_mongod(juju, substrate, app_name, uri, "rs.status()", expecting_output=True)

    if result.failed:
        return False

    election_metrics = result.data.get("electionCandidateMetrics", {})

    if not election_metrics:
        return False

    reason = election_metrics.get("lastElectionReason", "")
    election_date = election_metrics.get("lastElectionDate", {}).get("$date", None)
    if not reason.startswith("stepUpRequest"):
        logger.info(
            "Reason is %s, should be one of 'stepUpRequest' or 'stepUpRequestSkipDryRun'", reason
        )
        return False

    if not election_date:
        logger.info("Missing election date")
        return False

    election_ts = convert_time(election_date)

    if election_ts >= sigterm_time:
        return True

    logger.info("Election time is %s, but sigterm time is %s", election_ts, sigterm_time)
    return False


def all_db_processes_down(juju: jubilant.Juju, substrate: Substrate, app_name: str) -> bool:
    """Verifies that all units of the charm do not have the DB process running."""
    try:
        for attempt in Retrying(stop=stop_after_attempt(60), wait=wait_fixed(3)):
            with attempt:
                for unit in juju.status().get_units(app_name):
                    try:
                        processes = run_command_on_server(juju, substrate, unit, "pgrep -x mongod")
                    # This raises an error if there's no process to find.
                    except jubilant.CLIError as e:
                        processes = e.stdout
                    # splitting processes by "\n" results in one or more empty lines, hence we
                    # need to process these lines accordingly.
                    processes = [proc for proc in processes.split("\n") if len(proc) > 0]
                    if len(processes) > 0:
                        raise ProcessRunningError
    except RetryError:
        return False

    return True


def mongodb_unit_in_status(
    status: Status,
    substrate: Substrate,
    unit_to_check: str,
    unit_to_check_hostname: str,
    expected_status: str,
    username: str,
    password: str,
) -> bool:
    valid = True
    app_name = get_app_name_from_unit(unit_to_check)
    for unit_name, unit_status in status.get_units(app_name).items():
        if unit_name == unit_to_check:
            continue
        host = get_ip_from_unit(substrate, unit_status)
        uri = unit_uri(username=username, password=password, ip_address=host)
        with MongoClient(uri, directConnection=True) as client:
            data = client.admin.command("replSetGetStatus")
        found = False
        for member in data["members"]:
            data_unit_name = member["name"].split(":")[0]
            if data_unit_name == unit_to_check_hostname:
                valid &= member["stateStr"] == expected_status
                # We found the member, let's remember it.
                found = True
        # Add the clause that stores if we found the member or not.
        valid &= found
    return valid
