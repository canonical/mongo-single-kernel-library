from pathlib import Path

import pytest
import yaml
from ops.testing import Harness

from single_kernel_mongo.config.literals import SNAP
from single_kernel_mongo.lib.charms.operator_libs_linux.v2.snap import Snap, SnapState

from .mongodb_test_charm.src.charm import MongoTestCharm
from .mongos_test_charm.src.charm import MongosTestCharm

CONFIG = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/config.yaml").read_text()))
ACTIONS = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/actions.yaml").read_text()))
METADATA = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/metadata.yaml").read_text()))

MONGOS_ACTIONS = str(
    yaml.safe_load(Path("./tests/unit/mongos_test_charm/actions.yaml").read_text())
)
MONGOS_METADATA = str(
    yaml.safe_load(Path("./tests/unit/mongos_test_charm/metadata.yaml").read_text())
)


@pytest.fixture(autouse=True)
def tenacity_wait(mocker):
    mocker.patch("tenacity.nap.time")


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
def mock_fs_interactions(mocker) -> None:
    mocker.patch(
        "single_kernel_mongo.lib.charms.operator_libs_linux.v2.snap.Snap.present",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.delete")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.write")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.stop")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.update_env")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.copy_to_unit")
    mocker.patch("pathlib.Path.mkdir")


@pytest.fixture
def harness() -> Harness[MongoTestCharm]:
    harness = Harness(MongoTestCharm, meta=METADATA, actions=ACTIONS, config=CONFIG)
    harness.add_relation("database-peers", "database-peers")
    harness.begin()
    with harness.hooks_disabled():
        harness.add_storage(storage_name="mongodb", count=1, attach=True)
    return harness


@pytest.fixture
def mongos_harness() -> Harness[MongosTestCharm]:
    harness = Harness(MongosTestCharm, meta=MONGOS_METADATA, actions=MONGOS_ACTIONS)
    harness.add_relation("router-peers", "router-peers")
    harness.begin()
    return harness
