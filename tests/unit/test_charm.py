# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json

import pytest
from ops.pebble import PathError, ProtocolError
from ops.testing import ActionFailed, Harness
from pymongo.errors import ConfigurationError, ConnectionFailure, OperationFailure

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.statuses import LdapStatuses, MongoDBStatuses, MongodStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    ShardingMigrationError,
    WorkloadExecError,
    WorkloadNotReadyError,
    WorkloadServiceError,
)
from single_kernel_mongo.utils.mongo_connection import NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    CharmedBackupUser,
    CharmedMonitorUser,
    CharmedOperatorUser,
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
    harness.charm.model._storages = {"mongodb": None, "mongodb-logs": None}
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


def test_start_already_initialised(harness, mocker, mock_fs_interactions):
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
    # presets
    harness.set_leader(True)

    harness.charm.operator.state.db_initialised = True

    harness.charm.on.start.emit()

    # when the database has already been initialised we should not set up the replica set or
    # handle users
    init_replset.assert_not_called()
    init_user.assert_not_called()
    defer.assert_not_called()


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
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_operator_user"
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
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart",
        side_effect=WorkloadServiceError,
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False

    harness.charm.on.start.emit()

    # not being able to start exporter should not block repl set initiation
    assert harness.charm.operator.state.db_initialised


def test_start_fail_pbm_agent(harness, mocker, mock_fs_interactions):
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


def test_on_config_changed_invalid_role(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    with pytest.raises(ShardingMigrationError):
        harness.update_config({"role": "shard"})


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
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services"
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


def test_on_config_changed_upgrade_in_progress(harness, mocker):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocked_defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        return_value=True,
    )
    harness.update_config(
        {
            "ldap-query-template": "{PROVIDED_USER}",
        }
    )

    mocked_defer.assert_called()


def test_on_leader_elected(harness):
    state = harness.charm.operator.state
    assert state.get_keyfile() is None
    assert state.get_user_password(CharmedMonitorUser) == ""
    assert state.get_user_password(CharmedOperatorUser) == ""
    assert state.get_user_password(CharmedBackupUser) == ""
    harness.set_leader(True)
    assert len(state.get_keyfile()) == 1024
    assert len(state.get_user_password(CharmedMonitorUser)) == 32
    assert len(state.get_user_password(CharmedOperatorUser)) == 32
    assert len(state.get_user_password(CharmedBackupUser)) == 32


def test_on_leader_elected_dont_rotate_if_present(harness):
    state = harness.charm.operator.state
    harness.set_leader(True)
    operator_password = state.get_user_password(CharmedOperatorUser)
    harness.charm.on.leader_elected.emit()
    assert state.get_user_password(CharmedOperatorUser) == operator_password


def test_on_secret_changed(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, mongodb_name: str
):
    mocked = mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    harness.set_leader(True)
    password = "deadbeef"
    secret_label = f"{mongodb_name}.app"
    secret = harness.charm.operator.state.secrets.get(scope=Scope.APP)
    # breakpoint()
    content = secret.get_content()
    content["charmed-monitor-password"] = password
    secret.set_content(content)

    harness.charm.operator.update_secrets_and_restart(secret_label, secret.get_info().id)

    mocked.assert_called()
    assert (
        password in harness.charm.operator.mongodb_exporter_config_manager.build_parameters()[0][0]
    )


def test_on_secret_changed_unknown(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mock_get = mocker.patch("single_kernel_mongo.core.secrets.SecretCache.get")

    harness.charm.operator.update_secrets_and_restart("unknown", "kdfjqlmdfjldq")
    mock_get.assert_not_called()


def test_connect_to_mongo_exporter_on_set_password(harness, mocker, mock_fs_interactions):
    """Test configure_and_restart is called when the password is set for 'monitor' user."""
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password")
    connect_exporter = mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    harness.set_leader(True)

    harness.run_action("set-password", {"username": "monitor"})
    connect_exporter.assert_called()


def test_event_auto_reset_password_secrets_when_no_pw_value_shipped(
    harness, mocker, mock_fs_interactions
):
    """Test we correctly generate new password."""
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password")
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.configure_and_restart"
    )
    harness.set_leader(True)

    params = {"username": "monitor"}
    output = harness.run_action("get-password", params)

    pw1 = output.results["password"]
    assert pw1

    output = harness.run_action("set-password", params)
    pw2 = output.results["password"]
    assert pw2

    # Assert a new password has been created
    assert pw1 != pw2


@pytest.mark.skip_if_substrate("lxd")
def test_connect_mongodb_exporter_success(
    harness: Harness[MongoTestCharm], mocker, mongodb_hostname: str, substrate: Substrate
):
    """Tests the correct config is done."""
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.handle_licenses")
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.set_permissions")
    mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.exec")
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart")
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password")

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    if substrate == "microk8s":
        container = harness.model.unit.get_container("mongod")
        harness.charm.on.mongod_pebble_ready.emit(container)
    else:
        harness.charm.on.start.emit()

    password = harness.charm.operator.state.get_user_password(CharmedMonitorUser)

    uri_template = (
        "mongodb://monitor:{password}@{mongodb_hostname}:27017/admin?replicaSet=mongodb-k8s"
    )

    env = harness.charm.operator.mongodb_exporter_config_manager.get_environment()

    assert env == uri_template.format(password=password, mongodb_hostname=mongodb_hostname)

    params = {"username": "monitor", "password": "mongo123"}
    harness.run_action("set-password", params)

    password = harness.charm.operator.state.get_user_password(CharmedMonitorUser)

    new_uri = harness.charm.operator.mongodb_exporter_config_manager.get_environment()

    expected_uri = uri_template.format(password="mongo123", mongodb_hostname=mongodb_hostname)

    assert expected_uri == new_uri


def test_pbm_connect_no_password(harness: Harness[MongoTestCharm], mocker):
    mock_active = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.active")
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.backup_manager.configure_and_restart()

    mock_active.assert_not_called()


def test_pbm_connect_no_db_initialised(harness: Harness[MongoTestCharm], mocker):
    mock_active = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.active")
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.backup_manager.configure_and_restart()

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
    harness.charm.operator.backup_manager.configure_and_restart()
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

    harness.charm.operator.backup_manager.configure_and_restart()
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

    harness.charm.operator.backup_manager.configure_and_restart()
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
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        return_value=True,
    )
    spied = mocker.spy(harness.charm.operator, "new_peer")
    harness.set_leader(True)
    harness.add_relation_unit(rel.id, "mongodb/1")

    spied.assert_called()
    mock_on_relation_changed.assert_not_called()


def test_mongodb_relation_joined_all_replicas_not_ready(
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

    assert any(status == MongodStatuses.WAITING_RECONFIG.value for status in statuses)
    mocked_add_replset_member.assert_not_called()


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

    for exception, _ in PYMONGO_EXCEPTIONS:
        remove_replset.side_effect = exception
        # simulate 2nd MongoDB unit joining( need a unit to join before removing a unit)
        harness.add_relation_unit(rel.id, f"{mongodb_name}/1")
        harness.update_relation_data(rel.id, f"{mongodb_name}/1", PEER_ADDR[substrate])

        # simulate removing 2nd MongoDB unit
        harness.remove_relation_unit(rel.id, f"{mongodb_name}/1")

        remove_replset.assert_called()
        defer.assert_called()


def test_reconfigure_peer_not_ready(
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

    add_replset.assert_not_called()
    defer.assert_called()


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
