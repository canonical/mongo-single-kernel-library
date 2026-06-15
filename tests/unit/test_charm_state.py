import pytest
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import (
    PeerRelationNames,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.utils.mongodb_users import (
    CharmedBackupUser,
    CharmedOperatorUser,
    CharmedStatsUser,
)
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.integration.helpers.types import Substrate

PEER_ADDR = {
    "lxd": {"private-address": "127.4.5.6"},
    "microk8s": {"private-address": "mongodb-k8s-1.mongodb-k8s-endpoints"},
}


def test_config(harness: Harness[MongoTestCharm]):
    config = harness.charm.operator.state.config
    assert config.role == "replication"


def test_peer_units(harness: Harness[MongoTestCharm], mongodb_name: str):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    assert harness.charm.operator.state.peer_relation.id == rel.id  # type: ignore
    assert {unit.name for unit in harness.charm.operator.state.peers_units} == {f"{mongodb_name}/1"}


def test_users_secrets(harness: Harness[MongoTestCharm], mongodb_name: str):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore

    harness.set_leader(True)
    harness.charm.operator.new_leader()

    state = harness.charm.operator.state
    assert state.operator_config.password == state.secrets.get_for_key(
        Scope.APP, "charmed-operator-password"
    )
    assert state.stats_config.password == state.secrets.get_for_key(
        Scope.APP, "charmed-stats-password"
    )
    assert state.backup_config.password == state.secrets.get_for_key(
        Scope.APP, "charmed-backup-password"
    )


def test_app_peer_data(harness: Harness[MongoTestCharm], mongodb_name, substrate: Substrate):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.set_leader(True)
    state = harness.charm.operator.state

    assert state.app_peer_data.role == MongoDBRoles.REPLICATION
    assert not state.db_initialised
    assert state.app_peer_data.managed_users == set()
    assert len(state.get_keyfile() or "") == 1024
    assert state.app_peer_data.replica_set == mongodb_name

    assert not state.app_peer_data.is_user_created(CharmedStatsUser.username)
    assert not state.app_peer_data.is_user_created(CharmedBackupUser.username)
    assert not state.app_peer_data.is_user_created(CharmedOperatorUser.username)

    state.app_peer_data.set_user_created(CharmedStatsUser.username)
    assert state.app_peer_data.is_user_created(CharmedStatsUser.username)

    assert not state.app_peer_data.external_connectivity
    state.app_peer_data.external_connectivity = True
    assert state.app_peer_data.external_connectivity
    if substrate == "lxd":
        assert len(state.get_cluster_id()) == 8
    else:
        assert state.get_cluster_id() is None


def test_unit_peer_data(
    harness: Harness[MongoTestCharm], mongodb_name: str, substrate: Substrate, mongodb_hostname: str
):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.set_leader(True)
    state = harness.charm.operator.state

    assert state.unit_peer_data.internal_address == mongodb_hostname


def test_mongodb_status_user(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    state = harness.charm.operator.state
    password = state.get_user_password(user=CharmedStatsUser)
    assert state.stats_config.uri.startswith(
        f"mongodb://charmed-stats:{password}@127.0.0.1:27017/admin?"
    )


def test_is_shard_added_to_cluster_fail(
    harness: Harness[MongoTestCharm], mocker, mongodb_name: str
):
    """Tests that the shard cannot be considered added to cluster if shard_integrated is False."""
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.add_relation("sharding", "config-server")
    harness.set_leader(True)
    mock_get_shard_members = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members"
    )
    state = harness.charm.operator.state
    state.app_peer_data.role = MongoDBRoles.SHARD
    state.app_peer_data.mongos_hosts = ["a-host", "another-host"]
    state.shard_state.shard_integrated = False

    assert not state.is_shard_added_to_cluster()
    mock_get_shard_members.assert_not_called()


def test_is_shard_added_to_cluster_success(
    harness: Harness[MongoTestCharm], mocker, mongodb_name: str
):
    """Tests that the shard can be considered added to cluster if shard_integrated is True."""
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.add_relation("sharding", "config-server")
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        return_value=[mongodb_name, "another-replica-set"],
    )
    state = harness.charm.operator.state
    state.app_peer_data.role = MongoDBRoles.SHARD
    state.app_peer_data.mongos_hosts = ["a-host", "another-host"]
    state.shard_state.shard_integrated = True

    assert state.is_shard_added_to_cluster()


@pytest.mark.parametrize(
    "role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION, MongoDBRoles.SHARD]
)
def test_state_cluster_id_in_app_data(
    harness: Harness[MongoTestCharm], mongodb_name, substrate: Substrate, role
):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.set_leader(True)
    state = harness.charm.operator.state
    state.app_peer_data.role = role

    state.set_cluster_id("1234")
    if substrate == "lxd":
        assert state.get_cluster_id() == "1234"
    else:
        assert state.get_cluster_id() is None


@pytest.mark.parametrize(
    "role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.REPLICATION, MongoDBRoles.SHARD]
)
def test_state_cluster_id_is_none_in_app_data(
    harness: Harness[MongoTestCharm], mongodb_name, substrate: Substrate, role
):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.set_leader(True)
    state = harness.charm.operator.state
    state.app_peer_data.role = role
    state.remove_cluster_id()

    assert state.get_cluster_id() is None


def test_state_cluster_id_mongos_stored_in_app_peer_data(
    mongos_harness: Harness[MongosTestCharm], mongodb_name, substrate: Substrate
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.db_initialised = True
    state = mongos_harness.charm.operator.state
    state.set_cluster_id("1234")

    if substrate == "lxd":
        assert state.get_cluster_id() == "1234"
    else:
        assert state.get_cluster_id() is None


def test_state_cluster_id_mongos_is_none(mongos_harness: Harness[MongosTestCharm], mongodb_name):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.db_initialised = True
    state = mongos_harness.charm.operator.state
    state.remove_cluster_id()

    assert state.get_cluster_id() is None
