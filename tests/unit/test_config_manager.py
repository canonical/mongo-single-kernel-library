from pathlib import Path
from typing import Any

import pytest
from ops.model import Relation
from yaml import safe_dump

from single_kernel_mongo.config.literals import CharmKind, Substrates
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
from single_kernel_mongo.state.ldap_state import LdapState
from single_kernel_mongo.state.tls_state import TLSState
from single_kernel_mongo.workload import VMMongoDBWorkload, VMMongosWorkload


@pytest.mark.parametrize(
    "role,expected_parameter",
    (
        (MongoDBRoles.CONFIG_SERVER, {"sharding": {"clusterRole": "configsvr"}}),
        (MongoDBRoles.SHARD, {"sharding": {"clusterRole": "shardsvr"}}),
        (MongoDBRoles.REPLICATION, {}),
    ),
)
def test_mongodb_config_manager(mocker, role: MongoDBRoles, expected_parameter: dict[str, Any]):
    mock = mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.write",
    )

    mock_state = mocker.MagicMock(CharmState)
    mock_app_state = mocker.MagicMock(AppPeerReplicaSet)
    mock_state.app_peer_data = mock_app_state
    mock_state.tls = mocker.MagicMock(TLSState)
    mock_state.charm_role = ROLES[Substrates.VM][CharmKind.MONGOD]
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

    all_params = manager.build_config()

    assert port_parameter == {"net": {"port": 27017}}
    assert replset_option == {"replication": {"replSetName": "deadbeef"}}
    assert role_parameter == expected_parameter
    assert db_path_argument == {
        "storage": {
            "dbPath": f"{VM_PATH['mongod']['DATA']}",
            "journal": {"enabled": True},
        }
    }
    assert binding_ips == {"net": {"bindIpAll": True}}
    assert log_options == {
        "setParameter": {"processUmask": "037"},
        "systemLog": {
            "logRotate": "reopen",
            "logAppend": True,
            "path": f"{VM_PATH['mongod']['LOGS']}/mongodb.log",
            "destination": "file",
        },
    }

    assert audit_options == {
        "auditLog": {
            "destination": "file",
            "format": "JSON",
            "path": f"{VM_PATH['mongod']['LOGS']}/audit.log",
        }
    }

    assert auth_parameter == {
        "security": {
            "authorization": "enabled",
            "clusterAuthMode": "keyFile",
            "keyFile": f"{VM_PATH['mongod']['CONF']}/keyFile",
        }
    }
    assert tls_parameters == {}

    assert (
        all_params
        == {
            "net": {"bindIpAll": True, "port": 27017},
            "security": {
                "authorization": "enabled",
                "clusterAuthMode": "keyFile",
                "keyFile": f"{VM_PATH['mongod']['CONF']}/keyFile",
            },
            "setParameter": {"processUmask": "037"},
            "systemLog": {
                "logRotate": "reopen",
                "logAppend": True,
                "path": f"{VM_PATH['mongod']['LOGS']}/mongodb.log",
                "destination": "file",
            },
            "auditLog": {
                "destination": "file",
                "format": "JSON",
                "path": f"{VM_PATH['mongod']['LOGS']}/audit.log",
            },
            "replication": {"replSetName": "deadbeef"},
            "storage": {"dbPath": f"{VM_PATH['mongod']['DATA']}", "journal": {"enabled": True}},
        }
        | expected_parameter
    )

    manager.set_environment()

    mock.assert_called_once_with(
        Path(f"{VM_PATH['mongod']['CONF']}/mongod.conf"), safe_dump(all_params)
    )


def test_mongodb_ldap_config(mocker):
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.write",
    )

    mock_state = mocker.MagicMock(CharmState)
    mock_app_state = mocker.MagicMock(AppPeerReplicaSet)
    mock_state.app_peer_data = mock_app_state
    mock_state.tls = mocker.MagicMock(TLSState)
    mock_state.ldap = mocker.MagicMock(LdapState)

    mock_state.ldap.is_ready = lambda: True
    mock_state.ldap.relation = mocker.MagicMock(Relation)
    mock_state.ldap.bind_user = "cn=user,ou=group,dc=glauth,dc=com"
    mock_state.ldap.bind_password = "password"
    mock_state.ldap.base_dn = "dc=glauth,dc=com"
    mock_state.ldap.formatted_ldap_urls = ["ldap.glauth.com:3894"]
    mock_state.ldap.certificate = "beefdead"
    mock_state.ldap.ca = "deadbeef"
    mock_state.ldap.chain = ["feeddead"]

    mock_state.charm_role = ROLES[Substrates.VM][CharmKind.MONGOD]
    mock_state.app_peer_data.replica_set = "deadbeef"
    mock_state.is_role = lambda x: False
    mock_state.app_peer_data.role = MongoDBRoles.REPLICATION
    mock_state.tls.internal_enabled = False
    mock_state.tls.external_enabled = False
    workload = VMMongoDBWorkload(VM_MONGOD, None)
    config = MongoDBCharmConfig()
    manager = MongoDBConfigManager(
        config,
        mock_state,
        workload,
    )
    ldap_config = manager.ldap_parameters["security"]["ldap"]

    assert ldap_config["servers"] == "ldap.glauth.com:3894"
    assert ldap_config["bind"]["queryPassword"] == "password"
    assert ldap_config["bind"]["queryUser"] == "cn=user,ou=group,dc=glauth,dc=com"
    assert ldap_config["transportSecurity"] == "tls"


def test_mongos_config_manager(mocker):
    mock = mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.write",
    )
    mock_state = mocker.MagicMock(CharmState)
    mock_state.app_peer_data = mocker.MagicMock(AppPeerReplicaSet)
    mock_state.charm_role = ROLES[Substrates.VM][CharmKind.MONGOS]
    mock_state.substrate = Substrates.VM
    mock_state.cluster = mocker.MagicMock(ClusterState)
    mock_state.cluster.config_server_uri = "mongodb://config-server-url"
    mock_state.tls = mocker.MagicMock(TLSState)
    mock_state.app_peer_data.external_connectivity = False
    mock_state.tls.internal_enabled = False
    mock_state.tls.external_enabled = False
    mock_state.ldap.is_ready = lambda: False
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

    all_params = manager.build_config()

    assert port_parameter == {"net": {"port": 27018}}
    assert binding_ips == {
        "net": {
            "bindIp": f"{VM_PATH['mongod']['VAR']}/mongodb-27018.sock",
            "unixDomainSocket": {
                "filePermissions": "0766",
            },
        }
    }
    assert log_options == {
        "setParameter": {"processUmask": "037"},
        "systemLog": {
            "logRotate": "reopen",
            "logAppend": True,
            "path": f"{VM_PATH['mongod']['LOGS']}/mongodb.log",
            "destination": "file",
        },
    }

    assert audit_options == {
        "auditLog": {
            "destination": "file",
            "format": "JSON",
            "path": f"{VM_PATH['mongod']['LOGS']}/audit.log",
        }
    }
    assert auth_parameter == {
        "security": {
            "clusterAuthMode": "keyFile",
            "keyFile": f"{VM_PATH['mongod']['CONF']}/keyFile",
        }
    }
    assert tls_parameters == {}
    assert config_server_db_parameter == {"sharding": {"configDB": "mongodb://config-server-url"}}

    assert all_params == {
        "net": {
            "bindIp": f"{VM_PATH['mongod']['VAR']}/mongodb-27018.sock",
            "unixDomainSocket": {
                "filePermissions": "0766",
            },
            "port": 27018,
        },
        "security": {
            "clusterAuthMode": "keyFile",
            "keyFile": f"{VM_PATH['mongod']['CONF']}/keyFile",
        },
        "setParameter": {"processUmask": "037"},
        "systemLog": {
            "logRotate": "reopen",
            "logAppend": True,
            "path": f"{VM_PATH['mongod']['LOGS']}/mongodb.log",
            "destination": "file",
        },
        "auditLog": {
            "destination": "file",
            "format": "JSON",
            "path": f"{VM_PATH['mongod']['LOGS']}/audit.log",
        },
        "sharding": {"configDB": "mongodb://config-server-url"},
    }
    manager.set_environment()
    mock.assert_called_once_with(
        Path(f"{VM_PATH['mongod']['CONF']}/mongos.conf"), safe_dump(all_params)
    )


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

    assert manager.auth_parameter == {
        "security": {
            "authorization": "enabled",
            "clusterAuthMode": "x509",
        },
        "net": {
            "tls": {
                "allowInvalidCertificates": True,
                "clusterCAFile": f"{VM_PATH['mongod']['CONF']}/internal-ca.crt",
                "clusterFile": f"{VM_PATH['mongod']['CONF']}/internal-cert.pem",
            }
        },
    }
    assert manager.tls_parameters == {
        "net": {
            "tls": {
                "CAFile": f"{VM_PATH['mongod']['CONF']}/external-ca.crt",
                "certificateKeyFile": f"{VM_PATH['mongod']['CONF']}/external-cert.pem",
                "mode": "preferTLS",
                "disabledProtocols": "TLS1_0,TLS1_1",
            }
        },
    }


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
    assert manager.config_server_db_parameter == {
        "sharding": {"configDB": "deadbeef/127.0.0.1:27017"}
    }
