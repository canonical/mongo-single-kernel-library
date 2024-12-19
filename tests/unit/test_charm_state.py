import pytest
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.utils.mongodb_users import BackupUser, MonitorUser, OperatorUser

from .helpers import patch_network_get
from .mongodb_test_charm.src.charm import MongoTestCharm

PEER_ADDR = {"private-address": "127.4.5.6"}


@patch_network_get(private_address="1.1.1.1")
def test_app_hosts(harness: Harness[MongoTestCharm]):
    rel_id = harness.charm.model.get_relation(PeerRelationNames.PEERS.value).id  # type: ignore
    harness.add_relation_unit(rel_id, "test-mongodb/1")
    harness.update_relation_data(rel_id, "test-mongodb/1", PEER_ADDR)
    resulting_ips = harness.charm.operator.state.app_hosts
    expected_ips = {"1.1.1.1", "127.4.5.6"}
    assert expected_ips == resulting_ips


def test_config(harness: Harness[MongoTestCharm]):
    config = harness.charm.operator.state.config
    assert config.role == "replication"
    assert not config.auto_delete


def test_peer_units(harness: Harness[MongoTestCharm]):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, "test-mongodb/1")  # type: ignore
    assert harness.charm.operator.state.peer_relation.id == rel.id  # type: ignore
    assert {unit.name for unit in harness.charm.operator.state.peers_units} == {"test-mongodb/1"}


def test_users_secrets(harness: Harness[MongoTestCharm]):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, "test-mongodb/1")  # type: ignore

    harness.set_leader(True)
    harness.charm.operator.on_leader_elected()

    state = harness.charm.operator.state
    assert state.operator_config.password == state.secrets.get_for_key(
        Scope.APP, "operator-password"
    )
    assert state.monitor_config.password == state.secrets.get_for_key(Scope.APP, "monitor-password")
    assert state.backup_config.password == state.secrets.get_for_key(Scope.APP, "backup-password")


def test_app_peer_data(harness: Harness[MongoTestCharm]):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, "test-mongodb/1")  # type: ignore
    harness.set_leader(True)
    state = harness.charm.operator.state

    assert state.app_peer_data.role == MongoDBRoles.REPLICATION
    assert not state.db_initialised
    assert state.app_peer_data.managed_users == set()
    assert len(state.get_keyfile() or "") == 1024
    assert state.app_peer_data.replica_set == "test-mongodb"

    assert not state.app_peer_data.is_user_created(MonitorUser.username)
    assert not state.app_peer_data.is_user_created(BackupUser.username)
    assert not state.app_peer_data.is_user_created(OperatorUser.username)

    state.app_peer_data.set_user_created(MonitorUser.username)
    assert state.app_peer_data.is_user_created(MonitorUser.username)

    assert not state.app_peer_data.external_connectivity
    state.app_peer_data.external_connectivity = True
    assert state.app_peer_data.external_connectivity

    with pytest.raises(ValueError):
        state.app_peer_data.external_connectivity = 1  # type: ignore

    with pytest.raises(ValueError):
        state.app_peer_data.db_initialised = 0  # type: ignore


@patch_network_get(private_address="1.1.1.1")
def test_unit_peer_data(harness: Harness[MongoTestCharm]):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, "test-mongodb/1")  # type: ignore
    harness.set_leader(True)
    state = harness.charm.operator.state

    assert state.unit_peer_data.host == "1.1.1.1"
    assert state.unit_peer_data.internal_address == "1.1.1.1"
