import pytest

from single_kernel_mongo.config.literals import RoleEnum, Substrates
from single_kernel_mongo.config.models import ROLES, VM_MONGOD, VM_MONGOS, VM_PATH
from single_kernel_mongo.core.structured_config import (
    MongoDBCharmConfig,
    MongoDBRoles,
    MongosCharmConfig,
)
from single_kernel_mongo.managers.config import (
    MongoDBConfigManager,
    MongosConfigManager,
)
from single_kernel_mongo.state.app_peer_state import AppPeerReplicaSet
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.cluster_state import ClusterState
from single_kernel_mongo.state.tls_state import TLSState
from single_kernel_mongo.workload import VMMongoDBWorkload, VMMongosWorkload


@pytest.mark.parametrize(
    "role,expected_parameter",
    (
        (MongoDBRoles.CONFIG_SERVER, ["--configsvr"]),
        (MongoDBRoles.SHARD, ["--shardsvr"]),
        (MongoDBRoles.REPLICATION, []),
    ),
)
def test_mongodb_config_manager(mocker, role: MongoDBRoles, expected_parameter: list):
    mock = mocker.patch(
        "single_kernel_mongo.lib.charms.operator_libs_linux.v1.snap.Snap.set",
    )

    mock_state = mocker.MagicMock(CharmState)
    mock_app_state = mocker.MagicMock(AppPeerReplicaSet)
    mock_state.app_peer_data = mock_app_state
    mock_state.tls = mocker.MagicMock(TLSState)
    mock_state.charm_role = ROLES[Substrates.VM][RoleEnum.MONGOD]
    mock_state.app_peer_data.replica_set = "deadbeef"
    mock_state.app_peer_data.role = role
    mock_state.tls.internal_enabled = False
    mock_state.tls.external_enabled = False
    workload = VMMongoDBWorkload(VM_MONGOD, None)
    config = MongoDBCharmConfig()
    manager = MongoDBConfigManager(
        config,
        mock_state,
        workload,
    )

    port_parameter = manager.port_parameter
    replset_option = manager.replset_option
    role_parameter = manager.role_parameter
    db_path_argument = manager.db_path_argument
    binding_ips = manager.binding_ips
    log_options = manager.log_options
    audit_options = manager.audit_options
    auth_parameter = manager.auth_parameter
    tls_parameters = manager.tls_parameters

    all_params = manager.build_parameters()

    assert port_parameter == ["--port 27017"]
    assert replset_option == ["--replSet=deadbeef"]
    assert role_parameter == expected_parameter
    assert db_path_argument == [f"--dbpath={VM_PATH['mongod']['DATA']}"]
    assert binding_ips == ["--bind_ip_all"]
    assert log_options == [
        "--setParameter processUmask=037",
        "--logRotate reopen",
        "--logappend",
        f"--logpath={VM_PATH['mongod']['LOGS']}/mongodb.log",
    ]
    assert audit_options == [
        "--auditDestination=file",
        "--auditFormat=JSON",
        f"--auditPath={VM_PATH['mongod']['LOGS']}/audit.log",
    ]
    assert auth_parameter == [
        "--auth",
        "--clusterAuthMode=keyFile",
        f"--keyFile={VM_PATH['mongod']['CONF']}/keyFile",
    ]
    assert tls_parameters == []

    assert all_params == [
        binding_ips,
        port_parameter,
        auth_parameter,
        tls_parameters,
        log_options,
        audit_options,
        replset_option,
        role_parameter,
        db_path_argument,
    ]
    manager.set_environment()

    expected = " ".join([item for params in all_params for item in params])
    mock.assert_called_once_with({"mongod-args": expected})


def test_mongos_config_manager(mocker):
    mock = mocker.patch(
        "single_kernel_mongo.lib.charms.operator_libs_linux.v1.snap.Snap.set",
    )
    mock_state = mocker.MagicMock(CharmState)
    mock_state.app_peer_data = mocker.MagicMock(AppPeerReplicaSet)
    mock_state.charm_role = ROLES[Substrates.VM][RoleEnum.MONGOS]
    mock_state.cluster = mocker.MagicMock(ClusterState)
    mock_state.cluster.config_server_uri = "mongodb://config-server-url"
    mock_state.tls = mocker.MagicMock(TLSState)
    mock_state.app_peer_data.external_connectivity = False
    mock_state.tls.internal_enabled = False
    mock_state.tls.external_enabled = False
    workload = VMMongosWorkload(VM_MONGOS, None)
    config = MongosCharmConfig()
    manager = MongosConfigManager(
        config,
        workload,
        mock_state,
    )

    port_parameter = manager.port_parameter
    binding_ips = manager.binding_ips
    log_options = manager.log_options
    audit_options = manager.audit_options
    auth_parameter = manager.auth_parameter
    tls_parameters = manager.tls_parameters
    config_server_db_parameter = manager.config_server_db_parameter

    all_params = manager.build_parameters()

    assert port_parameter == ["--port 27018"]
    assert binding_ips == [
        f"--bind-ip {VM_PATH['mongod']['VAR']}/mongodb-27018.sock",
        "--filePermissions 0766",
    ]
    assert log_options == [
        "--setParameter processUmask=037",
        "--logRotate reopen",
        "--logappend",
        f"--logpath={VM_PATH['mongod']['LOGS']}/mongodb.log",
    ]
    assert audit_options == [
        "--auditDestination=file",
        "--auditFormat=JSON",
        f"--auditPath={VM_PATH['mongod']['LOGS']}/audit.log",
    ]
    assert auth_parameter == [
        "--auth",
        "--clusterAuthMode=keyFile",
        f"--keyFile={VM_PATH['mongod']['CONF']}/keyFile",
    ]
    assert tls_parameters == []
    assert config_server_db_parameter == ["--configdb mongodb://config-server-url"]

    assert all_params == [
        binding_ips,
        port_parameter,
        auth_parameter,
        tls_parameters,
        log_options,
        audit_options,
        config_server_db_parameter,
    ]
    manager.set_environment()
    expected_params = " ".join(item for param in all_params for item in param)
    mock.assert_called_once_with({"mongos-args": expected_params})


def test_mongodb_config_manager_tls_enabled(mocker):
    mock_state = mocker.MagicMock(CharmState)
    mock_app_state = mocker.MagicMock(AppPeerReplicaSet)
    mock_state.app_peer_data = mock_app_state
    mock_state.tls = mocker.MagicMock(TLSState)
    mock_state.app_peer_data.replica_set = "deadbeef"
    mock_state.app_peer_data.role = MongoDBRoles.REPLICATION
    mock_state.tls.internal_enabled = True
    mock_state.tls.external_enabled = True
    workload = VMMongoDBWorkload(VM_MONGOD, None)
    config = MongoDBCharmConfig()
    manager = MongoDBConfigManager(
        config,
        mock_state,
        workload,
    )

    assert manager.auth_parameter == [
        "--auth",
        "--clusterAuthMode=x509",
        "--tlsAllowInvalidCertificates",
        f"--tlsClusterCAFile={VM_PATH['mongod']['CONF']}/internal-ca.crt",
        f"--tlsClusterFile={VM_PATH['mongod']['CONF']}/internal-cert.pem",
    ]
    assert manager.tls_parameters == [
        f"--tlsCAFile={VM_PATH['mongod']['CONF']}/external-ca.crt",
        f"--tlsCertificateKeyFile={VM_PATH['mongod']['CONF']}/external-cert.pem",
        "--tlsMode=preferTLS",
        "--tlsDisabledProtocols=TLS1_0,TLS1_1",
    ]


def test_mongos_default_config_server(mocker):
    mock_state = mocker.MagicMock(CharmState)
    mock_state.app_peer_data = mocker.MagicMock(AppPeerReplicaSet)
    mock_state.app_peer_data.replica_set = "deadbeef"
    mock_state.cluster = mocker.MagicMock(ClusterState)
    mock_state.cluster.config_server_uri = ""
    mock_state.tls = mocker.MagicMock(TLSState)
    mock_state.app_peer_data.external_connectivity = False
    mock_state.tls.internal_enabled = False
    mock_state.tls.externalenabled = False
    workload = VMMongoDBWorkload(VM_MONGOD, None)
    config = MongosCharmConfig()
    manager = MongosConfigManager(
        config,
        workload,
        mock_state,
    )
    assert manager.config_server_db_parameter == ["--configdb deadbeef/127.0.0.1:27017"]
