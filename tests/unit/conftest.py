from pathlib import Path

import pytest
import yaml
from ops.testing import Harness

from single_kernel_mongo.config.literals import SNAP
from single_kernel_mongo.lib.charms.operator_libs_linux.v2.snap import Snap, SnapState
from tests.integration.helpers.types import Substrate

CONFIG = str(yaml.safe_load(Path("./tests/charms/mongodb_test_charm/config.yaml").read_text()))
ACTIONS = str(yaml.safe_load(Path("./tests/charms/mongodb_test_charm/actions.yaml").read_text()))
METADATA = str(yaml.safe_load(Path("./tests/charms/mongodb_test_charm/metadata.yaml").read_text()))

MONGOS_ACTIONS = str(
    yaml.safe_load(Path("./tests/charms/mongos_test_charm/actions.yaml").read_text())
)
MONGOS_METADATA = str(
    yaml.safe_load(Path("./tests/charms/mongos_test_charm/metadata.yaml").read_text())
)


@pytest.fixture
def harness(substrate: Substrate, mongod_base_path: Path) -> Harness:
    if substrate == "lxd":
        from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm as TestCharm
    else:
        from tests.charms.mongodb_k8s_test_charm.src.charm import (
            MongoKubernetesTestCharm as TestCharm,
        )

    config = str(yaml.safe_load((mongod_base_path / "config.yaml").read_text()))
    actions = str(yaml.safe_load((mongod_base_path / "actions.yaml").read_text()))
    metadata = str(yaml.safe_load((mongod_base_path / "metadata.yaml").read_text()))

    harness = Harness(TestCharm, meta=metadata, actions=actions, config=config)
    if substrate == "microk8s":
        mongo_resource = {
            "registrypath": "mongo:4.4",
        }
        harness.add_oci_resource("mongodb-image", mongo_resource)
    harness.add_relation("database-peers", "database-peers")
    harness.add_relation("status-peers", "mongodb")
    harness.add_relation("ldap-peers", "ldap-peers")
    harness.add_relation("upgrade-version-a", "upgrade-version-a")
    harness.begin()

    if substrate == "microk8s":
        harness.charm.operator.observability_manager = None
        container = harness.model.unit.get_container("mongod")
        harness.set_can_connect(container, True)
    with harness.hooks_disabled():
        harness.add_storage(storage_name="mongodb", count=1, attach=True)

    if substrate == "microk8s":
        with harness.hooks_disabled():
            harness.add_storage(storage_name="mongodb-logs", count=1, attach=True)

    return harness


@pytest.fixture
def mongos_harness(substrate: Substrate, mongos_base_path: Path) -> Harness:
    if substrate == "lxd":
        from tests.charms.mongos_test_charm.src.charm import MongosTestCharm as TestCharm
    else:
        from tests.charms.mongos_k8s_test_charm.src.charm import (
            MongosKubernetesTestCharm as TestCharm,
        )

    if substrate == "microk8s":
        config = str(yaml.safe_load((mongos_base_path / "config.yaml").read_text()))
    else:
        config = None
    actions = str(yaml.safe_load((mongos_base_path / "actions.yaml").read_text()))
    metadata = str(yaml.safe_load((mongos_base_path / "metadata.yaml").read_text()))

    harness = Harness(TestCharm, meta=metadata, actions=actions, config=config)
    harness.add_relation("status-peers", "mongos")
    harness.add_relation("ldap-peers", "ldap-peers")
    harness.add_relation("router-peers", "router-peers")
    harness.begin()
    if substrate == "microk8s":
        container = harness.model.unit.get_container("mongos")
        harness.set_can_connect(container, True)

    return harness


@pytest.fixture
def mongodb_name(substrate: Substrate):
    if substrate == "lxd":
        return "mongodb"
    return "mongodb-k8s"


@pytest.fixture
def mongos_name(substrate: Substrate):
    if substrate == "lxd":
        return "mongos"
    return "mongos-k8s"


@pytest.fixture(autouse=True)
def tenacity_wait(mocker):
    mocker.patch("tenacity.nap.time")


@pytest.fixture(autouse=True)
def get_charm_internal_revision(mocker, substrate: Substrate):
    mocker.patch(
        "single_kernel_mongo.core.workload.WorkloadBase.get_internal_revision", return_value="1"
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.get_charm_revision", return_value="1"
    )
    mocker.patch(
        "data_platform_helpers.version_check.CrossAppVersionChecker.set_version_on_related_app"
    )
    mocker.patch(
        "single_kernel_mongo.core.version_checker.VersionChecker.get_cluster_mismatched_revision_status",
        return_value=None,
    )
    if substrate == "microk8s":
        mocker.patch(
            "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
            new_callable=mocker.PropertyMock(return_value=False),
        )
        mocker.patch("single_kernel_mongo.managers.k8s.K8sManager.get_partition", return_value=0)
        mocker.patch("single_kernel_mongo.managers.k8s.K8sManager.set_partition", return_value=0)
        mocker.patch("single_kernel_mongo.managers.k8s.K8sManager.get_pod", return_value=0)


@pytest.fixture(autouse=True)
def mongod_ready(mocker):
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready", return_value=True
    )


@pytest.fixture(autouse=True)
def mock_snap_cache(mocker):
    mocker.patch(
        "single_kernel_mongo.lib.charms.operator_libs_linux.v2.snap.SnapCache.__getitem__",
        return_value=Snap(
            "charmed-mongodb",
            state=SnapState.Available,
            channel=SNAP.channel,
            revision=SNAP.revision,
            confinement="classic",
            apps=None,
        ),
    )


def setup_secrets(harness: Harness) -> None:
    harness.set_leader(True)  # This runs the on_leader_elected event.
    harness.set_leader(False)


@pytest.fixture
def mock_fs_interactions(mocker, substrate: Substrate) -> None:
    if substrate == "lxd":
        mocker.patch(
            "single_kernel_mongo.lib.charms.operator_libs_linux.v2.snap.Snap.present",
            new_callable=mocker.PropertyMock,
            return_value=True,
        )
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.delete")
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.write")
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start")
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.stop")
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.restart")
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.update_env")
        mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.copy_to_unit")
    else:
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.exec")
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.delete")
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.write")
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start")
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.stop")
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.mkdir")
        mocker.patch(
            "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active",
            return_value=True,
        )
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.update_env")
        mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.copy_to_unit")
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart")
    mocker.patch("pathlib.Path.mkdir")
    mocker.patch("pathlib.Path.write_text")
    mocker.patch("builtins.open")


@pytest.fixture
def mongodb_hostname(substrate: Substrate) -> str:
    if substrate == "lxd":
        return "10.0.0.10"
    return "mongodb-k8s-0.mongodb-k8s-endpoints"


@pytest.fixture
def second_hostname(substrate: Substrate) -> str:
    if substrate == "lxd":
        return "10.0.0.11"
    return "mongodb-k8s-1.mongodb-k8s-endpoints"
