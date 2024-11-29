from pathlib import Path

import pytest
import yaml
from ops.testing import Harness

from .mongodb_test_charm.src.charm import MongoTestCharm

CONFIG = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/config.yaml").read_text()))
ACTIONS = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/actions.yaml").read_text()))
METADATA = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/metadata.yaml").read_text()))


@pytest.fixture(autouse=True)
def tenacity_wait(mocker):
    mocker.patch("tenacity.nap.time")


def setup_secrets(harness: Harness) -> None:
    harness.set_leader(True)  # This runs the on_leader_elected event.
    harness.set_leader(False)


@pytest.fixture
def mock_fs_interactions(mocker) -> None:
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.delete")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.write")
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
