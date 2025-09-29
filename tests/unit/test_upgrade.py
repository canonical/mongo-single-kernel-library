# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import httpx
import pytest
from lightkube import ApiError
from ops.testing import Harness
from tenacity import Future, RetryError

from single_kernel_mongo.config.literals import UnitState
from single_kernel_mongo.core.kubernetes_upgrades import KubernetesUpgrade
from single_kernel_mongo.exceptions import (
    DeployedWithoutTrustError,
    UnhealthyUpgradeError,
)
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.integration.helpers.types import Substrate


@pytest.fixture
def mock_upgrade(mocker):
    """Fixture to simulate an upgrade in progress."""
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=True),
    )


def test_on_config_changed_during_ugprade_fails(
    harness: Harness[MongoTestCharm], mocker, mock_upgrade
):
    defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch("single_kernel_mongo.state.charm_state.CharmState.is_role", return_value=False)

    harness.charm.on.config_changed.emit()

    defer.assert_called()


@pytest.mark.parametrize(("handler",), (("relation_joined",), ("relation_changed",)))
def test_on_relation_handler(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, mock_upgrade, handler: str
):
    """Verifies that peer relation events are blocked on upgrade."""
    defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=True),
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True

    relation = harness.charm.model.get_relation("database-peers")

    getattr(harness.charm.on[relation.name], handler).emit(relation)

    defer.assert_called()


@pytest.mark.skip_if_substrate("lxd")
@pytest.mark.parametrize(
    ("status_code", "expected_error"), ((403, DeployedWithoutTrustError), (500, ApiError))
)
def test_lightkube_errors(
    harness: Harness[MongoTestCharm], mocker, status_code: int, expected_error
):
    api_error = ApiError(
        request=httpx.Request(url="http://controller/call", method="GET"),
        response=httpx.Response(409, json={"message": "bad call", "code": status_code}),
    )
    mocker.patch("single_kernel_mongo.managers.k8s.K8sManager.get_partition", side_effect=api_error)
    with pytest.raises(expected_error):
        KubernetesUpgrade(
            harness.charm.operator,
            harness.charm.operator.workload,
            harness.charm.operator.state,
            harness.charm.operator.substrate,
        )


@pytest.mark.parametrize(
    ("unit_version", "app_version", "outdated_in_status"),
    (
        ("6.0.6", "6.0.6", False),
        ("6.0.7", "6.0.6", True),
        ("6.0.6", "6.0.7", True),
    ),
)
def test_get_unit_healthy_status(
    harness: Harness[MongoTestCharm],
    substrate: Substrate,
    mocker,
    unit_version: str,
    app_version: str,
    outdated_in_status: bool,
):
    """Verifies that the unit reports the correct health status."""
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.app_workload_container_version",
        new_callable=mocker.PropertyMock(return_value=app_version),
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.unit_workload_container_version",
        new_callable=mocker.PropertyMock(return_value=unit_version),
    )
    status = harness.charm.operator.upgrade_manager._upgrade._get_unit_healthy_status()
    assert status.status == "active"
    if substrate == "microk8s":
        assert ("(restart pending)" in status.message) == outdated_in_status
    else:
        assert ("(outdated)" in status.message) == outdated_in_status


@pytest.mark.parametrize(
    (
        "cluster_healthy_return",
        "is_cluster_able_to_read_write_return",
        "initial_unit_state",
        "is_deferred",
    ),
    [
        [None, True, "restarting", False],
        [None, True, "restarting", False],
        [None, False, "restarting", True],
        [None, False, "restarting", True],
        [
            RetryError(Future(1)),
            False,
            "restarting",
            True,
        ],
    ],
)
def test_run_post_upgrade_checks(
    harness,
    mocker,
    cluster_healthy_return,
    is_cluster_able_to_read_write_return,
    initial_unit_state,
    is_deferred,
):
    """Tests the run post upgrade checks branching."""
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades.GenericMongoDBUpgradeManager.wait_for_cluster_healthy",
        return_value=cluster_healthy_return,
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades.GenericMongoDBUpgradeManager.is_cluster_able_to_read_write",
        return_value=is_cluster_able_to_read_write_return,
    )

    harness.charm.operator.state.unit_upgrade_peer_data.unit_state = UnitState(initial_unit_state)

    if is_deferred:
        with pytest.raises(UnhealthyUpgradeError):
            harness.charm.operator.upgrade_manager.run_post_upgrade_checks(False)
        assert harness.charm.operator.state.unit_upgrade_peer_data.unit_state == UnitState(
            initial_unit_state
        )
    else:
        harness.charm.operator.upgrade_manager.run_post_upgrade_checks(False)
        assert harness.charm.operator.state.unit_upgrade_peer_data.unit_state == UnitState.HEALTHY
