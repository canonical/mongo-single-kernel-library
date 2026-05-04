# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json

import pytest
from data_platform_helpers.advanced_statuses.models import StatusObject
from ops import BlockedStatus
from ops.model import ModelError
from ops.pebble import PathError, ProtocolError
from ops.testing import ActionFailed, Harness
from pymongo.errors import ConfigurationError, ConnectionFailure, OperationFailure

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.models import (
    BackupState,
    PasswordManagementContext,
    PasswordManagementState,
)
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import (
    LdapStatuses,
    MongoDBStatuses,
    MongodStatuses,
    PasswordManagementStatuses,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    ShardingMigrationError,
    WorkloadExecError,
    WorkloadNotReadyError,
    WorkloadServiceError,
)
from single_kernel_mongo.utils.mongo_connection import NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    CharmedBackupUser,
    CharmedLogRotateUser,
    CharmedOperatorUser,
    CharmedStatsUser,
    InternalUsers,
)
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.integration.helpers.types import Substrate

PEER_ADDR = {
    "lxd": {"private-address": "127.4.5.6"},
    "microk8s": {"private-address": "mongodb-k8s-1.mongodb-k8s-endpoints"},
}
PYMONGO_EXCEPTIONS = [
    (ConnectionFailure("error message"), ConnectionFailure),
    (ConfigurationError("error message"), ConfigurationError),
    (OperationFailure("error message"), OperationFailure),
]

VALID_SYSTEM_USERS = {
    "charmed-operator": "123",
    "charmed-stats": "abc",
    "charmed-logrotate": "something",
    "charmed-backup": "123abc",
}

INVALID_SYSTEM_USERS = {"invalid-user": "123"}


@pytest.mark.skip_if_substrate("microk8s")
def test_install_blocks_snap_install_failure(harness, mocker):
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.install", side_effect=WorkloadNotReadyError
    )
    with pytest.raises(WorkloadNotReadyError):
        harness.charm.on.install.emit()


@pytest.mark.skip_if_substrate("lxd")
def test_mongod_pebble_ready(harness, mocker):
    """Tests that under regular conditions, the service is set and defer has not been called."""
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator._initialise_replica_set"
    )
    mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.exec")
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.handle_licenses")
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.set_permissions")
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.set_feature_compatibility_version"
    )
    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.build_local_tls_directory")
    defer = mocker.patch("ops.framework.EventBase.defer")
    expected_plan = {
        "services": {
            "mongod": {
                "user": "mongodb",
                "group": "mongodb",
                "override": "replace",
                "summary": "mongod",
                "command": "/bin/bash /bin/start-mongod.sh",
                "environment": {"MONGOD_ARGS": ""},
                "startup": "enabled",
            },
        },
    }

    harness.set_leader(True)

    # Get the mongod container from the model
    container = harness.model.unit.get_container("mongod")

    # Emit the PebbleReadyEvent carrying the mongod container
    harness.charm.on.mongod_pebble_ready.emit(container)

    # Get the plan now we've run PebbleReady
    updated_plan = harness.get_container_pebble_plan("mongod").to_dict()

    # Check we've got the plan we expected
    assert expected_plan == updated_plan
    service = harness.model.unit.get_container("mongod").get_service("mongod")
    assert service.is_running()

    defer.assert_not_called()


@pytest.mark.skip_if_substrate("lxd")
def test_pebble_ready_container_cannot_connect(harness, mocker, mock_fs_interactions):
    """Test verifies behavior when cannot connect to container in pebble ready function.

    Verifies that when a failure to connect to container results in a deferral and that no
    efforts to set keyFile or add/replan layers are made.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    push_keyfile_to_workload = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.handle_licenses"
    )
    container = harness.model.unit.get_container("mongod")
    harness.set_can_connect(container, False)

    # Emit the PebbleReadyEvent carrying the mongod container
    harness.charm.on.mongod_pebble_ready.emit(container)

    push_keyfile_to_workload.assert_not_called()
    defer.assert_called()


@pytest.mark.skip_if_substrate("lxd")
def test_pebble_ready_push_keyfile_to_workload_failure(harness, mocker, mock_fs_interactions):
    """Test verifies behavior when setting keyfile fails.

    Verifies that when a failure to set keyfile occurs that there is no attempt to add layers
    or replan the container.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    push_keyfile_to_workload = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.handle_licenses"
    )
    set_perms = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.set_permissions"
    )
    # presets
    harness.set_leader(True)
    container = harness.model.unit.get_container("mongod")
    harness.set_can_connect(container, True)

    for exception in [
        PathError("kind", "message"),
        ProtocolError("kind", "message"),
    ]:
        push_keyfile_to_workload.side_effect = exception

        # Emit the PebbleReadyEvent carrying the mongod container
        harness.charm.on.mongod_pebble_ready.emit(container)

        set_perms.assert_not_called()
        defer.assert_called()


@pytest.mark.skip_if_substrate("lxd")
def test_pebble_ready_no_storage_yet(harness, mocker, mock_fs_interactions):
    """Test to ensure that the pebble ready event is deferred until the storage is ready."""
    defer = mocker.patch("ops.framework.EventBase.defer")
    configure = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator._configure_workloads"
    )
    # presets
    container = harness.model.unit.get_container("mongod")
    harness.set_can_connect(container, True)

    # Mock storages
    harness.charm.model._storages = {"data": None, "logs": None}
    # Emit the PebbleReadyEvent carrying the mock_container
    harness.charm.on.mongod_pebble_ready.emit(container)
    configure.assert_not_called()
    defer.assert_called()


@pytest.mark.skip_if_substrate("lxd")
def test_start_container_cannot_connect(harness, mocker, mock_fs_interactions):
    """Tests inability to connect results in deferral.

    Verifies that if connection is not possible, that there are no attempts to set up the
    replica set or handle users.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    init_replset = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    init_users = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_charm_admin_users"
    )
    # presets
    harness.set_leader(True)
    container = harness.model.unit.get_container("mongod")
    harness.set_can_connect(container, False)

    harness.charm.on.start.emit()

    # when cannot connect to container we should not set up the replica set or handle users
    init_replset.assert_not_called()
    init_users.assert_not_called()

    # verify app data
    assert harness.charm.operator.state.db_initialised is False
    defer.assert_called()


def test_start_not_ready(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=False)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start", return_value=True
    )
    patched_mongo_initialise = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.setup_systemd_overrides")

    harness.set_leader(True)
    harness.charm.on.start.emit()
    patched_mongo_initialise.assert_not_called()
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=harness.charm.operator.name
    )
    assert statuses[0] == MongoDBStatuses.WAITING_FOR_MONGODB_START.value


def test_start_failure_doesnt_init(harness, mocker, mock_fs_interactions):
    open_ports_mock = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.open_ports"
    )
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.start",
        side_effect=WorkloadServiceError,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start",
        side_effect=WorkloadServiceError,
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")

    patched_mongo_initialise = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    harness.set_leader(True)
    harness.charm.on.start.emit()
    open_ports_mock.assert_not_called()
    patched_mongo_initialise.assert_not_called()


def test_on_start_mongod_not_ready_defer(harness, mocker, mock_fs_interactions):
    def mock_exec(command, *_, **__):
        if command[0] == "open-port":
            raise WorkloadExecError("open-port", 1, None, None)

    harness.charm.workload.exec = mock_exec
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start", return_value=True
    )
    mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.get_env")

    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=False),
    )
    patched_mongo_initialise = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    harness.set_leader(True)
    harness.charm.on.start.emit()
    patched_mongo_initialise.assert_not_called()


@pytest.mark.skip_if_substrate("microk8s")
def test_start_unable_to_open_tcp_doesnt_init(harness, mocker, mock_fs_interactions):
    # This also tests that we call the hook on the workload.
    def mock_exec(command, *_, **__):
        if command[0] == "open-port":
            raise WorkloadExecError("open-port", 1, None, None)

    patched_mongo_initialise = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )

    harness.charm.workload.exec = mock_exec
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start", return_value=True
    )
    harness.set_leader(True)
    harness.charm.on.start.emit()
    patched_mongo_initialise.assert_not_called()


def test_start_success(harness, mocker, mock_fs_interactions):
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator._configure_workloads"
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.get_env")
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start", return_value=True
    )
    mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.get_env")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=True),
    )
    patched_mongo_initialise_replica_set = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    patched_mongo_initialise_user = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_charm_admin_users"
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.on.start.emit()
    patched_mongo_initialise_replica_set.assert_called()
    patched_mongo_initialise_user.assert_called()

    assert harness.charm.operator.state.db_initialised


def test_start_already_initialised(harness, mocker, mock_refresh, mock_fs_interactions):
    """Tests that if the replica set has already been set up that we return.

    Verifies that if the replica set is already set up that no attempts to set it up again are
    made and that there are no attempts to set up users.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    init_replset = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    init_user = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_charm_admin_users"
    )
    set_fcv = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.set_feature_compatibility_version"
    )
    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.setup_systemd_overrides")
    # presets
    harness.set_leader(True)

    harness.charm.operator.state.db_initialised = True

    harness.charm.on.start.emit()

    # when the database has already been initialised we should not set up the replica set or
    # handle users
    init_replset.assert_not_called()
    init_user.assert_not_called()
    defer.assert_not_called()
    set_fcv.assert_called()


def test_start_mongod_error_initialising_replica_set(
    harness,
    mocker,
    mock_fs_interactions,
):
    """Tests that failure to initialise replica set set is properly handled.

    Verifies that when there is a failure to initialise replica set the defer is called and
    db_initialised is not set to initialised.
    """
    init_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.init_replset"
    )
    defer = mocker.patch("ops.framework.EventBase.defer")
    init_users = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_charm_admin_users"
    )
    # presets
    harness.set_leader(True)

    for exception, _ in PYMONGO_EXCEPTIONS:
        init_replset.side_effect = exception
        harness.charm.on.start.emit()

        assert not harness.charm.operator.state.db_initialised

        init_users.assert_not_called()
        defer.assert_called()

        # verify app data
        assert not harness.charm.operator.state.db_initialised


def test_start_mongod_error_overseeing_users(
    harness,
    mocker,
    mock_fs_interactions,
):
    """Tests failures related to pymongo are properly handled when overseeing users.

    Verifies that when there is a failure to oversee users that we defer and do not set the
    data base to initialised.
    """
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.init_replset")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.initialise_charm_admin_users")
    defer = mocker.patch("ops.framework.EventBase.defer")
    user_exists = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.user_exists"
    )

    # presets
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.add_relation("database", "client-app")

    for exception, _ in PYMONGO_EXCEPTIONS:
        user_exists.side_effect = exception
        harness.charm.on.start.emit()

        assert not harness.charm.operator.state.db_initialised

        defer.assert_called()


def test_start_mongod_error_initialising_users(
    harness,
    mocker,
    mock_fs_interactions,
):
    """Tests that failure to initialise users set is properly handled.

    Verifies that when there is a failure to initialise users that overseeing users is not
    called.
    """
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.init_replset")
    defer = mocker.patch("ops.framework.EventBase.defer")
    init_operator_user = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_charmed_operator_user"
    )
    init_user = mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.initialise_user")
    # presets
    harness.set_leader(True)

    init_operator_user.side_effect = WorkloadExecError("command", 0, "stdout", "stderr")
    harness.charm.on.start.emit()

    init_user.assert_not_called()
    defer.assert_called()

    # verify app data
    assert not harness.charm.operator.state.db_initialised


def test_start_fail_mongodb_exporter(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=True),
    )
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.initialise_charm_admin_users")
    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.build_local_tls_directory")
    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.setup_systemd_overrides")
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False

    harness.charm.on.start.emit()

    # not being able to start exporter should not block repl set initiation
    assert harness.charm.operator.state.db_initialised


def test_start_fail_pbm_agent(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.setup_systemd_overrides")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.start", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=True),
    )
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.initialise_charm_admin_users")
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart",
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart",
        side_effect=WorkloadServiceError,
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False

    harness.charm.on.start.emit()

    # not being able to start exporter should not block repl set initiation
    assert harness.charm.operator.state.db_initialised


def test_on_config_changed_inmpossible_to_change_role(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    with pytest.raises(ShardingMigrationError):
        harness.update_config({"role": "shard"})


def test_on_config_changed_invalid_role(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.update_config({"role": "invalidrole"})
    harness.evaluate_status()
    assert harness.charm.app.status == BlockedStatus("The role config option is invalid.")


def test_on_config_changed_no_role_yet(harness: Harness[MongoTestCharm], mocker):
    mocked_defer = mocker.patch("ops.framework.EventBase.defer")
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.UNKNOWN
    harness.update_config({"role": "shard"})
    mocked_defer.assert_called()


def test_on_config_changed_invalid_ldap_user_to_dn_mapping(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.update_config({"ldap-user-to-dn-mapping": "invalid"})

    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=harness.charm.operator.name
    )
    assert statuses[0] == LdapStatuses.INVALID_LDAP_USER_MAPPING.value


def test_on_config_changed_invalid_ldap_query_template_provided_user(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    valid_mapping = [
        {
            "match": "([^@]+)@([^@\\.]+)\\.example\\.com",
            "substitution": "CN={0},CN=Users,DC={1},DC=example,DC=com",
        }
    ]

    harness.update_config(
        {
            "ldap-user-to-dn-mapping": json.dumps(valid_mapping),
            "ldap-query-template": "{PROVIDED_USER}",
        }
    )
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=harness.charm.operator.name
    )
    assert statuses[0] == LdapStatuses.INVALID_LDAP_QUERY_TEMPLATE.value


def test_on_config_changed_invalid_ldap_query_template_user(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.update_config(
        {
            "ldap-query-template": "{USER}",
        }
    )
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=harness.charm.operator.name
    )
    assert statuses[0] == LdapStatuses.INVALID_LDAP_QUERY_TEMPLATE.value


def test_on_config_changed_valid_ldap_query_template(harness, mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.async_restart_charm_services"
    )
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    valid_mapping = [
        {
            "match": "([^@]+)@([^@\\.]+)\\.example\\.com",
            "substitution": "CN={0},CN=Users,DC={1},DC=example,DC=com",
        }
    ]

    harness.update_config(
        {
            "ldap-user-to-dn-mapping": json.dumps(valid_mapping),
            "ldap-query-template": "{USER}",
        }
    )
    assert json.loads(harness.charm.operator.state.ldap.ldap_user_to_dn_mapping) == valid_mapping
    assert harness.charm.operator.state.ldap.ldap_query_template == "{USER}"


def test_on_config_changed_upgrade_in_progress(harness, mocker, mongodb_name):
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocked_defer = mocker.patch("ops.framework.EventBase.defer")
    harness.charm.operator.refresh.in_progress = True
    harness.update_config(
        {
            "ldap-query-template": "{PROVIDED_USER}",
            "system-users": f"{secret_id}",
        }
    )

    mocked_defer.assert_called()


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_config_changed_valid_system_users_password_is_updated(
    harness, mocker, mongodb_name, role, mock_fs_interactions
):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.update_config(
        {
            "role": f"{role.value}",
            "system-users": f"{secret_id}",
        }
    )
    set_user_password_mock.assert_has_calls(
        [
            mocker.call("charmed-operator", "123"),
            mocker.call("charmed-stats", "abc"),
            mocker.call("charmed-logrotate", "something"),
            mocker.call("charmed-backup", "123abc"),
        ],
        any_order=True,
    )
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses.root == []


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_config_changed_system_users_invalid_passwords(
    harness, mocker, mongodb_name, role, mock_fs_interactions
):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, INVALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.update_config(
        {
            "role": f"{role.value}",
            "system-users": f"{secret_id}",
        }
    )
    set_user_password_mock.assert_not_called()
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses[0] == PasswordManagementStatuses.INVALID_SYSTEM_USERS.value


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_config_changed_system_users_password_did_not_changed(
    harness, mocker, mongodb_name, role, mock_fs_interactions
):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "abc")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "123")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "something")
    harness.charm.operator.state.set_user_password(CharmedBackupUser, "123abc")
    harness.charm.operator.state.app_peer_data.role = role

    harness.update_config(
        {
            "role": f"{role.value}",
            "system-users": f"{secret_id}",
        }
    )

    set_user_password_mock.assert_not_called()
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses.root == []


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_config_changed_system_users_one_password_changed(
    harness, mocker, mongodb_name, role, mock_fs_interactions
):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "abc")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "123")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "something")
    harness.charm.operator.state.set_user_password(
        CharmedBackupUser, "this-is-a-different-password"
    )
    harness.charm.operator.state.app_peer_data.role = role

    harness.update_config(
        {
            "role": f"{role.value}",
            "system-users": f"{secret_id}",
        }
    )

    set_user_password_mock.assert_called_once()
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses.root == []


def test_on_config_changed_system_users_do_not_update_passwords_on_shard(
    harness, mocker, mongodb_name: str, mock_fs_interactions
):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.update_config(
        {
            "role": f"{MongoDBRoles.SHARD.value}",
            "system-users": f"{secret_id}",
        }
    )
    set_user_password_mock.assert_not_called()
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses[0] == PasswordManagementStatuses.PASSWORD_ON_SHARD.value


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_config_changed_system_users_secret_does_not_exist(
    harness, mocker, role, mock_fs_interactions
):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    defer = mocker.patch("ops.framework.EventBase.defer")
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.update_config(
        {
            "role": f"{role.value}",
            "system-users": "secret:1234-567443",
        }
    )
    set_user_password_mock.assert_not_called()
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses[0] == PasswordManagementStatuses.SECRET_NOT_FOUND.value
    defer.assert_not_called()


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_config_changed_system_users_fail_to_update_password(
    harness, mocker, mongodb_name, role, mock_fs_interactions
):
    defer = mocker.patch("ops.framework.EventBase.defer")
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
        side_effect=NotReadyError(),
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role

    harness.update_config(
        {
            "role": f"{role.value}",
            "system-users": f"{secret_id}",
        }
    )
    set_user_password_mock.assert_called_once()
    defer.assert_called_once()


def test_on_leader_elected_passwords_are_generated(harness):
    state = harness.charm.operator.state
    assert state.get_keyfile() is None
    for user in InternalUsers:
        assert state.get_user_password(user) == ""
    harness.set_leader(True)
    assert len(state.get_keyfile()) == 1024
    for user in InternalUsers:
        assert len(state.get_user_password(user)) == 32


def test_on_leader_elected_sets_password_from_secret_in_config(harness, mongodb_name):
    state = harness.charm.operator.state
    assert state.get_keyfile() is None
    for user in InternalUsers:
        assert state.get_user_password(user) == ""
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    with harness.hooks_disabled():
        harness.update_config(
            {
                "system-users": f"{secret_id}",
            }
        )
    harness.set_leader(True)
    assert state.get_user_password(CharmedOperatorUser) == "123"
    assert state.get_user_password(CharmedStatsUser) == "abc"
    assert state.get_user_password(CharmedLogRotateUser) == "something"
    assert state.get_user_password(CharmedBackupUser) == "123abc"


def test_on_leader_elected_sets_password_from_secret_in_config_only_some_users(
    harness, mongodb_name
):
    state = harness.charm.operator.state
    assert state.get_keyfile() is None
    for user in InternalUsers:
        assert state.get_user_password(user) == ""

    new_passwords = {
        "charmed-operator": "123",
        "charmed-stats": "abc",
    }

    secret_id = harness.add_model_secret(mongodb_name, new_passwords)
    with harness.hooks_disabled():
        harness.update_config(
            {
                "system-users": f"{secret_id}",
            }
        )
    harness.set_leader(True)
    assert state.get_user_password(CharmedOperatorUser) == "123"
    assert state.get_user_password(CharmedStatsUser) == "abc"
    assert len(state.get_user_password(CharmedLogRotateUser)) == 32
    assert len(state.get_user_password(CharmedBackupUser)) == 32


def test_on_leader_elected_failure_on_secret_obtained_from_config(harness):
    state = harness.charm.operator.state
    assert state.get_keyfile() is None
    for user in InternalUsers:
        assert state.get_user_password(user) == ""
    with harness.hooks_disabled():
        harness.update_config(
            {
                "system-users": "secret:123405663",
            }
        )
    harness.set_leader(True)
    for user in InternalUsers:
        assert len(state.get_user_password(user)) == 32


def test_on_leader_elected_dont_rotate_passwords_already_set(harness):
    state = harness.charm.operator.state
    harness.set_leader(True)
    operator_password = state.get_user_password(CharmedOperatorUser)
    stats_password = state.get_user_password(CharmedStatsUser)
    logrotate_password = state.get_user_password(CharmedLogRotateUser)
    backup_password = state.get_user_password(CharmedBackupUser)
    harness.charm.on.leader_elected.emit()
    assert state.get_user_password(CharmedOperatorUser) == operator_password
    assert state.get_user_password(CharmedStatsUser) == stats_password
    assert state.get_user_password(CharmedLogRotateUser) == logrotate_password
    assert state.get_user_password(CharmedBackupUser) == backup_password


def test_on_leader_elected_dont_rotate_cluster_id_already_set(harness):
    harness.set_leader(True)
    cluster_id = harness.charm.operator.state.app_peer_data.cluster_id
    harness.charm.on.leader_elected.emit()
    new_cluster_id = harness.charm.operator.state.app_peer_data.cluster_id

    assert len(cluster_id) == 8
    assert cluster_id == new_cluster_id


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_secret_changed_system_users_update_on_leader(harness, mocker, mongodb_name, role):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "aaaa")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "bbbb")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "cccc")
    harness.charm.operator.state.set_user_password(CharmedBackupUser, "dddd")
    harness.charm.operator.state.app_peer_data.role = role
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )

    harness.charm.operator.update_secrets_and_restart("label", secret_id)

    set_user_password_mock.assert_has_calls(
        [
            mocker.call("charmed-operator", "123"),
            mocker.call("charmed-stats", "abc"),
            mocker.call("charmed-logrotate", "something"),
            mocker.call("charmed-backup", "123abc"),
        ],
        any_order=True,
    )
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses.root == []


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_secret_changed_system_users_update_on_leader_invalid_passwords(
    harness, mocker, mongodb_name, role
):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, INVALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "aaaa")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "bbbb")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "cccc")
    harness.charm.operator.state.set_user_password(CharmedBackupUser, "dddd")
    harness.charm.operator.state.app_peer_data.role = role
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )

    with pytest.raises(NonDeferrableFailedHookChecksError):
        harness.charm.operator.update_secrets_and_restart("label", secret_id)

        set_user_password_mock.assert_not_called()
        statuses = harness.charm.operator.state.statuses.get(
            scope=Scope.APP, component=harness.charm.operator.name
        )
        assert statuses[0] == PasswordManagementStatuses.INVALID_SYSTEM_USERS.value


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_secret_changed_on_leader_not_system_users_secret(harness, mocker, mongodb_name, role):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "aaaa")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "bbbb")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "cccc")
    harness.charm.operator.state.set_user_password(CharmedBackupUser, "dddd")
    harness.charm.operator.state.app_peer_data.role = role
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )

    harness.charm.operator.update_secrets_and_restart("label", "other-secret-id")
    set_user_password_mock.assert_not_called()


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_on_secret_changed_system_users_update_during_upgrade(harness, mocker, mongodb_name, role):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    harness.charm.operator.refresh.in_progress = True
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "aaaa")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "bbbb")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "cccc")
    harness.charm.operator.state.set_user_password(CharmedBackupUser, "dddd")
    harness.charm.operator.state.app_peer_data.role = role
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )

    with pytest.raises(DeferrableFailedHookChecksError):
        harness.charm.operator.update_secrets_and_restart("label", secret_id)

    set_user_password_mock.assert_not_called()


def test_on_secret_changed_system_users_update_on_leader_shard(harness, mocker, mongodb_name):
    set_user_password_mock = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password"
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "aaaa")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "bbbb")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "cccc")
    harness.charm.operator.state.set_user_password(CharmedBackupUser, "dddd")
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{MongoDBRoles.SHARD.value}",
                "system-users": f"{secret_id}",
            }
        )

    harness.charm.operator.update_secrets_and_restart("label", secret_id)

    set_user_password_mock.assert_not_called()
    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.APP, component=harness.charm.operator.name
    )
    assert statuses[0] == PasswordManagementStatuses.PASSWORD_ON_SHARD.value


def test_leader_elected_invalid_role(harness: Harness[MongoTestCharm]):
    state = harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config({"role": "invalidrole"})

    assert state.is_role(MongoDBRoles.UNKNOWN)

    harness.set_leader(True)
    assert harness.charm.app.status == BlockedStatus("The role config option is invalid.")
    assert state.app_peer_data.role == MongoDBRoles.UNKNOWN

    harness.update_config({"role": "replication"})
    harness.set_leader(True)

    assert state.app_peer_data.role == MongoDBRoles.REPLICATION


def test_on_secret_changed_non_leader(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, mongodb_name: str
):
    mocked = mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    harness.set_leader(False)
    password = "deadbeef"
    secret_id = harness.add_model_secret(mongodb_name, {"charmed-stats-password": password})

    secret_label = f"{mongodb_name}.app"
    harness.charm.operator.update_secrets_and_restart(secret_label, secret_id)

    mocked.assert_called()


def test_on_secret_changed_unknown(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(False)
    mock_get = mocker.patch("single_kernel_mongo.core.secrets.SecretCache.get")

    harness.charm.operator.update_secrets_and_restart("unknown", "kdfjqlmdfjldq")
    mock_get.assert_not_called()


@pytest.mark.skip_if_substrate("lxd")
def test_connect_mongodb_exporter_success(
    harness: Harness[MongoTestCharm],
    mocker,
    mongodb_name,
):
    """Tests the correct config is done."""
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.handle_licenses")
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.set_permissions")
    mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.exec")
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart")
    mocker.patch("single_kernel_mongo.managers.config.LogRotateConfigManager.configure_and_restart")
    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.build_local_tls_directory")
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password")
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.set_feature_compatibility_version"
    )

    mongodb_hostname = "127.0.0.1"

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    container = harness.model.unit.get_container("mongod")
    harness.charm.on.mongod_pebble_ready.emit(container)

    password = harness.charm.operator.state.get_user_password(CharmedStatsUser)
    uri_template = (
        "mongodb://charmed-stats:{password}@{mongodb_hostname}:27017/admin?replicaSet=mongodb-k8s"
    )
    env = harness.charm.operator.mongodb_exporter_config_manager.get_environment()

    assert env == uri_template.format(password=password, mongodb_hostname=mongodb_hostname)

    local_system_users = {**VALID_SYSTEM_USERS, "charmed-stats": "mongo123"}
    secret_id = harness.add_model_secret(mongodb_name, local_system_users)
    harness.update_config(
        {
            "system-users": f"{secret_id}",
        }
    )

    password = harness.charm.operator.state.get_user_password(CharmedStatsUser)
    new_uri = harness.charm.operator.mongodb_exporter_config_manager.get_environment()
    expected_uri = uri_template.format(password="mongo123", mongodb_hostname=mongodb_hostname)

    assert expected_uri == new_uri


def test_pbm_connect_no_password(harness: Harness[MongoTestCharm], mocker):
    mock_active = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.active")
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.s3_backup_manager.configure_and_restart()

    mock_active.assert_not_called()


def test_pbm_connect_no_db_initialised(harness: Harness[MongoTestCharm], mocker):
    mock_active = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.active")
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.s3_backup_manager.configure_and_restart()

    mock_active.assert_not_called()


def test_pbm_connect_same_env(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.active",
        return_value=True,
    )
    mock_start = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.start")

    uri = harness.charm.operator.state.backup_config.uri
    mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.get_environment",
        return_value=uri,
    )
    harness.charm.operator.s3_backup_manager.configure_and_restart()
    mock_start.assert_not_called()


def test_pbm_connect_not_active(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.active",
        return_value=False,
    )
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.workload_present",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mock_start = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.start")
    mock_stop = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.stop")
    mock_set_env = mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.set_environment"
    )

    harness.charm.operator.s3_backup_manager.configure_and_restart()
    mock_start.assert_called()
    mock_stop.assert_called()
    mock_set_env.assert_called()


def test_pbm_connect_active_other_password(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.active",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.workload_present",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mock_start = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.start")
    mock_stop = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.stop")
    mock_set_env = mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.set_environment"
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.get_environment",
        return_value="deadbeef",
    )

    harness.charm.operator.s3_backup_manager.configure_and_restart()
    mock_start.assert_called()
    mock_stop.assert_called()
    mock_set_env.assert_called()


def test_relation_joined_non_leader_does_nothing(harness: Harness[MongoTestCharm], mocker):
    rel = harness.charm.operator.state.peer_relation
    mock_on_relation_changed = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.peer_changed"
    )
    spied = mocker.spy(harness.charm.operator, "new_peer")

    harness.set_leader(False)
    harness.add_relation_unit(rel.id, "mongodb/1")

    spied.assert_called()
    mock_on_relation_changed.assert_not_called()


def test_relation_joined_upgrade_in_progress_defers(harness: Harness[MongoTestCharm], mocker):
    rel = harness.charm.operator.state.peer_relation
    mock_on_relation_changed = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.peer_changed"
    )
    harness.charm.operator.refresh.in_progress = True
    spied = mocker.spy(harness.charm.operator, "new_peer")
    harness.set_leader(True)
    harness.add_relation_unit(rel.id, "mongodb/1")

    spied.assert_called()
    mock_on_relation_changed.assert_not_called()


def test_mongodb_relation_joined_all_replicas_not_ready_are_added(
    harness: Harness[MongoTestCharm], mocker, substrate: Substrate, mongodb_hostname: str
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mock_conn = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
    )
    mock_conn.return_value = False
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_members",
        return_value={mongodb_hostname},
    )
    mocked_add_replset_member = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.add_replset_member"
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart")

    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, "mongodb/1")
    harness.update_relation_data(rel.id, "mongodb/1", PEER_ADDR[substrate])

    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=harness.charm.operator.name
    )

    assert all(status != MongodStatuses.WAITING_RECONFIG.value for status in statuses)
    mocked_add_replset_member.assert_called()


def test_reconfigure_not_already_initialised(
    harness,
    mocker,
    mock_fs_interactions,
    substrate: Substrate,
    mongodb_name: str,
    mongodb_hostname: str,
    second_hostname: str,
):
    """Tests reconfigure does not execute when database has not been initialised.

    Verifies in case of relation_joined and relation departed, that when the the database has
    not yet been initialised that no attempts to remove/add units are made.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    connection = mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection")

    harness.set_leader(True)

    rel = harness.charm.model.get_relation("database-peers")

    for departed in [False, True]:
        if departed:
            connection.get_replset_members.return_value = {mongodb_hostname, second_hostname}
            harness.remove_relation_unit(rel.id, f"{mongodb_name}/1")
            connection.add_replset_member.assert_not_called()
        else:
            connection.get_replset_members.return_value = {mongodb_hostname}
            harness.add_relation_unit(rel.id, f"{mongodb_name}/1")
            harness.update_relation_data(rel.id, f"{mongodb_name}/1", PEER_ADDR[substrate])
            connection.remove_replset_member.assert_not_called()

    defer.assert_not_called()


def test_reconfigure_get_members_failure(
    harness,
    mocker,
    mock_fs_interactions,
    substrate: Substrate,
    mongodb_name: str,
):
    """Tests reconfigure does not execute when database has not been initialised.

    Verifies in case of relation_joined and relation departed, that when the the database has
    not yet been initialised that no attempts to remove/add units are made.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    add_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.add_replset_member"
    )
    remove_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.remove_replset_member"
    )
    get_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_members"
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True

    rel = harness.charm.model.get_relation("database-peers")

    for exception, _ in PYMONGO_EXCEPTIONS:
        get_replset.side_effect = exception
        for departed in [False, True]:
            if departed:
                harness.remove_relation_unit(rel.id, f"{mongodb_name}/1")
                add_replset.assert_not_called()
            else:
                harness.add_relation_unit(rel.id, f"{mongodb_name}/1")
                harness.update_relation_data(rel.id, f"{mongodb_name}/1", PEER_ADDR[substrate])
                remove_replset.assert_not_called()

            defer.assert_called()


def test_reconfigure_remove_members_failure(
    harness,
    mocker,
    mock_fs_interactions,
    substrate: Substrate,
    mongodb_name: str,
    second_hostname: str,
    mock_rollingops_manager,
):
    """Tests reconfigure does not proceed when unable to remove a member.

    Verifies in relation departed events, that when the database cannot remove a member that
    the event is deferred.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.add_replset_member")
    remove_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.remove_replset_member"
    )
    get_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_members"
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    get_replset.return_value = {mongodb_name, second_hostname}

    rel = harness.charm.model.get_relation("database-peers")

    exceptions = PYMONGO_EXCEPTIONS + [(NotReadyError, None)]

    for exception, _ in exceptions:
        remove_replset.side_effect = exception
        # simulate 2nd MongoDB unit joining( need a unit to join before removing a unit)
        harness.add_relation_unit(rel.id, f"{mongodb_name}/1")
        harness.update_relation_data(rel.id, f"{mongodb_name}/1", PEER_ADDR[substrate])

        # simulate removing 2nd MongoDB unit
        harness.remove_relation_unit(rel.id, f"{mongodb_name}/1")

        remove_replset.assert_called()
        mock_rollingops_manager.acquire_sync_lock.assert_called_with(
            backend_id="stop-replset-member",
            timeout=3 * 60,
        )
        defer.assert_called()


def test_reconfigure_peer_not_ready_replica_set_is_added(
    harness,
    mocker,
    mock_fs_interactions,
    substrate: Substrate,
    mongodb_name: str,
):
    """Tests reconfigure does not proceed when the adding member is not ready.

    Verifies in relation joined events, that when the adding member is not ready that the event
    is deferred.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    add_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.add_replset_member"
    )
    get_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_members"
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=False),
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    get_replset.return_value = {mongodb_name}

    rel = harness.charm.model.get_relation("database-peers")

    # simulate 2nd MongoDB unit joining( need a unit to join before removing a unit)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")
    harness.update_relation_data(rel.id, f"{mongodb_name}/1", PEER_ADDR[substrate])

    add_replset.assert_called()
    defer.assert_not_called()


def test_reconfigure_add_member_failure(
    harness,
    mocker,
    mock_fs_interactions,
    substrate: Substrate,
    mongodb_name: str,
):
    """Tests reconfigure does not proceed when unable to add a member.

    Verifies in relation joined events, that when the database cannot add a member that the
    event is deferred.
    """
    defer = mocker.patch("ops.framework.EventBase.defer")
    add_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.add_replset_member"
    )
    get_replset = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_members"
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    get_replset.return_value = {mongodb_name}

    rel = harness.charm.model.get_relation("database-peers")

    exceptions = PYMONGO_EXCEPTIONS + [(NotReadyError, None)]

    for exception, _ in exceptions:
        add_replset.side_effect = exception
        # simulate 2nd MongoDB unit joining( need a unit to join before removing a unit)
        harness.add_relation_unit(rel.id, f"{mongodb_name}/1")
        harness.update_relation_data(rel.id, f"{mongodb_name}/1", PEER_ADDR[substrate])

        add_replset.assert_called()
        defer.assert_called()


def test_on_relation_departed_not_leader(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    spied = mocker.spy(harness.charm.operator, "peer_leaving")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.process_added_units")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.update_app_relation_data")
    update_host_mock = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_hosts"
    )
    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, "mongodb/1")

    harness.set_leader(False)
    harness.remove_relation_unit(rel.id, "mongodb/1")

    spied.assert_called()
    update_host_mock.assert_not_called()


def test_on_relation_departed_leader(
    harness: Harness[MongoTestCharm],
    mocker,
    mock_fs_interactions,
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    spied = mocker.spy(harness.charm.operator, "peer_leaving")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.process_added_units")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.update_app_relation_data")
    update_host_mock = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_hosts"
    )
    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, "mongodb/1")

    harness.remove_relation_unit(rel.id, "mongodb/1")

    spied.assert_called()
    update_host_mock.assert_called()


def test_primary_db_not_initialised(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False

    with pytest.raises(ActionFailed):
        harness.run_action("get-primary")


def test_primary(harness: Harness[MongoTestCharm], mocker, mongodb_name, mongodb_hostname: str):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.primary",
        return_value=mongodb_hostname,
    )
    output = harness.run_action("get-primary")
    assert output.results["replica-set-primary"] == f"{mongodb_name}/0"


def test_primary_other_unit(
    harness: Harness[MongoTestCharm], mocker, mongodb_name: str, substrate: Substrate
):
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.process_added_units")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.update_app_relation_data")
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.primary",
        return_value=PEER_ADDR[substrate]["private-address"],
    )
    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")
    harness.update_relation_data(rel.id, f"{mongodb_name}/1", PEER_ADDR[substrate])
    output = harness.run_action("get-primary")
    assert output.results["replica-set-primary"] == f"{mongodb_name}/1"


@pytest.mark.parametrize(
    "role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION, MongoDBRoles.SHARD]
)
def test_password_management_context_system_users_not_set(harness, role):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(PasswordManagementState.EMPTY)
    assert expected_context == context


def test_password_management_context_shard_with_system_users(harness, mongodb_name):
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{MongoDBRoles.SHARD.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(PasswordManagementState.PASSWORD_ON_SHARD)
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_not_leader(harness, mongodb_name, role):
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.charm.operator.state.app_peer_data.role = role
    with harness.hooks_disabled():
        harness.set_leader(False)
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(PasswordManagementState.NOT_LEADER)
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_update_in_progress(harness, mocker, mongodb_name, role):
    harness.charm.operator.refresh.in_progress = True
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.UPGRADE_RUNNING,
        "Cannot update passwords while an upgrade is in progress.",
    )
    assert expected_context == context


@pytest.mark.parametrize("pbm_state", [BackupState.BACKUP_RUNNING, BackupState.RESTORE_RUNNING])
@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_backup_running(harness, mocker, mongodb_name, role, pbm_state):
    mocker.patch(
        "single_kernel_mongo.managers.backups.common.CommonBackupManager.backup_state",
        return_value=pbm_state,
    )
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.BACKUP_RUNNING,
        "Cannot update passwords while a backup/restore is in progress.",
    )
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_invalid_secret_format(harness, role):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": "12345",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.INVALID_CONTENT,
        "Invalid secret URI '12345'. It must start with 'secret:'",
    )
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_secret_not_found(harness, role):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": "secret:123445",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.SECRET_NOT_FOUND, "The secret 'secret:123445' does not exist."
    )
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_secret_not_granted(harness, mocker, role):
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.get_secret_from_id",
        side_effect=ModelError,
    )
    secret_id = harness.add_model_secret("some_application", VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.SECRET_NOT_GRANTED,
        f"Secret '{secret_id}' has not be granted to the application.",
    )
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_invalid_system_users_content(harness, mongodb_name, role):
    secret_id = harness.add_model_secret(mongodb_name, INVALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.INVALID_CONTENT,
        "Invalid system-users secret content. Unexpected usernames provided: invalid-user",
    )
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_need_password_update(harness, mongodb_name, role):
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.NEED_PASSWORD_UPDATE, system_users=VALID_SYSTEM_USERS
    )
    assert expected_context == context


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION])
def test_password_management_context_password_did_not_change(harness, mongodb_name, role):
    secret_id = harness.add_model_secret(mongodb_name, VALID_SYSTEM_USERS)
    harness.set_leader(True)
    harness.charm.operator.state.set_user_password(CharmedStatsUser, "abc")
    harness.charm.operator.state.set_user_password(CharmedOperatorUser, "123")
    harness.charm.operator.state.set_user_password(CharmedLogRotateUser, "something")
    harness.charm.operator.state.set_user_password(CharmedBackupUser, "123abc")
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )
    context = harness.charm.operator.get_password_management_context()
    expected_context = PasswordManagementContext(
        PasswordManagementState.EMPTY, system_users=VALID_SYSTEM_USERS
    )
    assert expected_context == context


@pytest.mark.parametrize(
    ("role", "rel_name", "status"),
    (
        (
            MongoDBRoles.REPLICATION,
            RelationNames.SHARDING,
            MongoDBStatuses.INVALID_SHARDING_REL.value,
        ),
        (
            MongoDBRoles.REPLICATION,
            RelationNames.CONFIG_SERVER,
            MongoDBStatuses.INVALID_SHARDING_REL.value,
        ),
        (MongoDBRoles.CONFIG_SERVER, RelationNames.DATABASE, MongoDBStatuses.INVALID_DB_REL.value),
        (MongoDBRoles.SHARD, RelationNames.DATABASE, MongoDBStatuses.INVALID_DB_REL.value),
        (
            MongoDBRoles.SHARD,
            RelationNames.CONFIG_SERVER,
            MongoDBStatuses.INVALID_CFG_SRV_ON_SHARD_REL.value,
        ),
        (
            MongoDBRoles.CONFIG_SERVER,
            RelationNames.SHARDING,
            MongoDBStatuses.INVALID_SHARD_ON_CFG_SRV_REL.value,
        ),
        (
            MongoDBRoles.REPLICATION,
            RelationNames.CLUSTER,
            MongoDBStatuses.INVALID_MONGOS_REL.value,
        ),
        (
            MongoDBRoles.SHARD,
            RelationNames.CLUSTER,
            MongoDBStatuses.INVALID_MONGOS_REL.value,
        ),
        (MongoDBRoles.REPLICATION, RelationNames.DATABASE, None),
        (MongoDBRoles.CONFIG_SERVER, RelationNames.CONFIG_SERVER, None),
        (MongoDBRoles.CONFIG_SERVER, RelationNames.CLUSTER, None),
        (MongoDBRoles.SHARD, RelationNames.SHARDING, None),
    ),
)
def test_get_relation_feasible_status(
    harness: Harness[MongoTestCharm],
    role: MongoDBRoles,
    rel_name: RelationNames,
    status: StatusObject | None,
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role

    computed_status = harness.charm.operator.get_relation_feasible_status(rel_name.value)
    assert computed_status == status
