# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import PosixPath

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from httpx import Request, Response
from lightkube.core.exceptions import ApiError
from ops.testing import Harness
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import MongosStatuses
from single_kernel_mongo.exceptions import DeferrableError
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm


def test_start(mongos_harness: Harness[MongosTestCharm], mocker, mock_fs_interactions):
    mocked_copy = mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.copy_to_unit")

    mongos_harness.charm.on.start.emit()
    assert mongos_harness.charm.unit.status == as_status(MongosStatuses.NEED_CONF_SERVER.value)

    mocked_copy.assert_has_calls(
        [
            mocker.call(
                PosixPath("LICENSE"),
                PosixPath("src/licenses/LICENSE-charm"),
            ),
            mocker.call(
                PosixPath("/snap/charmed-mongodb/current/licenses/LICENSE-snap"),
                PosixPath("src/licenses/LICENSE-snap"),
            ),
            mocker.call(
                PosixPath("/snap/charmed-mongodb/current/licenses/LICENSE-mongodb-exporter"),
                PosixPath("src/licenses/LICENSE-mongodb-exporter"),
            ),
            mocker.call(
                PosixPath("/snap/charmed-mongodb/current/licenses/LICENSE-percona-backup-mongodb"),
                PosixPath("src/licenses/LICENSE-percona-backup-mongodb"),
            ),
            mocker.call(
                PosixPath("/snap/charmed-mongodb/current/licenses/LICENSE-percona-server"),
                PosixPath("src/licenses/LICENSE-percona-server"),
            ),
        ]
    )


def test_share_connection_info_fail_db_not_initialised(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = False

    mocked_share = mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator._share_configuration"
    )

    mongos_harness.charm.operator.share_connection_info()

    mocked_share.assert_not_called()


def test_share_connection_info_fail_not_leader(mongos_harness: Harness[MongosTestCharm], mocker):
    mongos_harness.set_leader(False)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True

    mocked_share = mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator._share_configuration"
    )

    mongos_harness.charm.operator.share_connection_info()

    mocked_share.assert_not_called()


@pytest.mark.parametrize(
    ("call_exception", "expected_error"),
    (
        (
            PyMongoError("blah"),
            DeferrableError,
        ),
        (
            ApiError(
                request=Request(url="http://controller/call", method="GET"),
                response=Response(409, json={"message": "bad call", "code": 404}),
            ),
            DeferrableError,
        ),
        (
            ApiError(
                request=Request(url="http://controller/call", method="GET"),
                response=Response(409, json={"message": "bad call", "code": 500}),
            ),
            ApiError,
        ),
    ),
)
def test_share_connection_info_fail_exception(
    mongos_harness: Harness[MongosTestCharm], mocker, call_exception, expected_error
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True

    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator._share_configuration",
        side_effect=call_exception,
    )

    with pytest.raises(expected_error):
        mongos_harness.charm.operator.share_connection_info()


@pytest.mark.parametrize(
    ("databag", "expected_db", "expected_extra_user_roles", "expected_connectivity"),
    (
        (
            {
                "database": "test",
                "extra-user-roles": "test-role,admin",
                "external-node-connectivity": "false",
            },
            "test",
            {"test-role", "admin"},
            False,
        ),
        (
            {
                "database": "test",
                "external-node-connectivity": "false",
            },
            "test",
            {"default"},
            False,
        ),
        (
            {
                "database": "test",
                "external-node-connectivity": "true",
            },
            "test",
            {"default"},
            True,
        ),
    ),
)
def test_proxy_information_to_client_and_handler_connectivity(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
    databag,
    expected_db,
    expected_extra_user_roles,
    expected_connectivity,
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    mock_open_port = mocker.patch("ops.model.Unit.open_port")

    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        databag,
    )

    assert mongos_harness.charm.operator.state.app_peer_data.database == expected_db
    assert (
        mongos_harness.charm.operator.state.app_peer_data.extra_user_roles
        == expected_extra_user_roles
    )
    assert (
        mongos_harness.charm.operator.state.app_peer_data.external_connectivity
        == expected_connectivity
    )

    if expected_connectivity:
        mock_open_port.assert_called()
