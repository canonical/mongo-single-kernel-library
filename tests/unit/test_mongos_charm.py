# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from ops.model import WaitingStatus
from ops.testing import Harness

from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WorkloadNotReadyError,
)
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm

CLUSTER_ALIAS = "cluster"
MONGOS_SOCKET_URI_FMT = "%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock"


@pytest.mark.skip_if_substrate("microk8s")
def test_install_blocks_snap_install_failure(mongos_harness: Harness[MongosTestCharm], mocker):
    mock_exec = mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
    mocker.patch.object(mongos_harness.charm.status_handler, "set_running_status")
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.install", side_effect=WorkloadNotReadyError
    )
    with pytest.raises(WorkloadNotReadyError):
        mongos_harness.charm.on.install.emit()
    mock_exec.assert_any_call(["systemctl", "restart", "snapd.service"])
    mock_exec.assert_any_call(["systemctl", "is-active", "--quiet", "snapd.service"])


@pytest.mark.skip_if_substrate("lxd")
def test_pebble_ready_container_cannot_connect(
    mongos_harness: Harness[MongosTestCharm], mocker, mock_fs_interactions
):
    """Test verifies behavior when cannot connect to container in pebble ready function.

    Verifies that when a failure to connect to container results in a deferral and that no
    efforts to set keyFile or add/replan layers are made.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    push_keyfile_to_workload = mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.handle_licenses"
    )
    container = mongos_harness.model.unit.get_container("mongos")
    mongos_harness.set_can_connect(container, False)

    # Emit the PebbleReadyEvent carrying the mongod container
    mongos_harness.charm.on.mongos_pebble_ready.emit(container)

    mongos_harness.evaluate_status()
    assert mongos_harness.charm.unit.status == WaitingStatus(
        "Waiting for MongoDB to be installed..."
    )
    push_keyfile_to_workload.assert_not_called()
    defer.assert_called()


def test_get_keyfile_contents_no_secret(mongos_harness: Harness[MongosTestCharm]):
    """Tests file isn't checked if secret isn't set."""
    assert mongos_harness.charm.operator.state.get_keyfile() is None


def test_proceed_on_broken_event(mongos_harness: Harness[MongosTestCharm]):
    """Tests that proceed on broken event only returns true when relation is broken.

    Note: relation broken events also occur when scaling down related applications so it is
    important to differentiate the two.
    """
    rel = mongos_harness.charm.operator.state.peer_relation

    # case 1: no relation departed check has run
    with pytest.raises(DeferrableFailedHookChecksError):
        assert not mongos_harness.charm.operator.assert_proceed_on_broken_event(rel)

    # case 2: relation departed check ran, but is due to scale down
    mongos_harness.charm.operator.state.set_scaling_down(rel.id, mongos_harness._unit_name)
    with pytest.raises(NonDeferrableFailedHookChecksError):
        mongos_harness.charm.operator.assert_proceed_on_broken_event(rel)

    # case 3: relation departed check ran and is due to a broken event
    mongos_harness.charm.operator.state.set_scaling_down(rel.id, "other")
    mongos_harness.charm.operator.assert_proceed_on_broken_event(rel)


def test_status_shows_mongos_waiting(
    mongos_harness: Harness[MongosTestCharm], mocker, mock_fs_interactions
):
    """Tests that mongos accurately reports waiting status."""
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.is_mongos_running",
        return_value=False,
    )
    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.tls_statuses", return_value=[]
    )
    # A running config server is a requirement to start for mongos
    mongos_harness.charm.on.update_status.emit()

    mongos_harness.evaluate_status()

    assert mongos_harness.model.unit.status.name == "blocked"
    mongos_harness.add_relation("cluster", "config-server")
    mongos_harness.charm.on.update_status.emit()

    mongos_harness.evaluate_status()
    assert mongos_harness.model.unit.status.name == "waiting"
