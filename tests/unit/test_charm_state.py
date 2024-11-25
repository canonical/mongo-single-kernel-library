from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import RelationNames

from .helpers import patch_network_get
from .mongodb_test_charm.src.charm import MongoTestCharm

PEER_ADDR = {"private-address": "127.4.5.6"}


@patch_network_get(private_address="1.1.1.1")
def test_app_hosts(harness: Harness[MongoTestCharm]):
    rel_id = harness.charm.model.get_relation(RelationNames.PEERS.value).id  # type: ignore
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
    rel = harness.charm.model.get_relation(RelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, "test-mongodb/1")  # type: ignore
    assert harness.charm.operator.state.peer_relation.id == rel.id  # type: ignore
    assert {unit.name for unit in harness.charm.operator.state.peers_units} == {"test-mongodb/1"}


def test_users_secrets(harness: Harness[MongoTestCharm]):
    rel = harness.charm.model.get_relation(RelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, "test-mongodb/1")  # type: ignore

    harness.set_leader(True)
    harness.charm.operator.on_leader_elected()

    state = harness.charm.operator.state
    assert state.operator_config.password == state.secrets.get_for_key(
        Scope.APP, "operator-password"
    )
    assert state.monitor_config.password == state.secrets.get_for_key(Scope.APP, "monitor-password")
    assert state.backup_config.password == state.secrets.get_for_key(Scope.APP, "backup-password")
