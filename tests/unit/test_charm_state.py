import json

import pytest
from ops.model import SecretNotFoundError
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import (
    PeerRelationNames,
    RelationNames,
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
from tests.unit.helpers import GROUP_DN

PEER_ADDR = {
    Substrate.lxd: {"private-address": "127.4.5.6"},
    Substrate.k8s: {"private-address": "mongodb-k8s-1.mongodb-k8s-endpoints"},
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
    if substrate == Substrate.lxd:
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


def test_peer_database_addresses(
    harness: Harness[MongoTestCharm], mongodb_name: str, substrate: Substrate
):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.charm.operator.state.unit_peer_data.database_address = "10.0.0.1"
    harness.update_relation_data(
        rel.id,  # type: ignore
        f"{mongodb_name}/1",
        {"database-address": "10.0.0.2"},
    )

    assert set(harness.charm.operator.state.peer_database_addresses) == {
        "10.0.0.1",
        "10.0.0.2",
    }


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_local_auth_restrictions_use_peer_database_addresses(
    harness: Harness[MongoTestCharm], mongodb_name: str, substrate: Substrate
):
    rel = harness.charm.model.get_relation(PeerRelationNames.PEERS.value)
    harness.add_relation_unit(rel.id, f"{mongodb_name}/1")  # type: ignore
    harness.add_relation_unit(rel.id, f"{mongodb_name}/2")  # type: ignore
    harness.charm.operator.state.unit_peer_data.database_address = "172.31.15.253"
    harness.update_relation_data(
        rel.id,  # type: ignore
        f"{mongodb_name}/1",
        {"database-address": "172.31.24.68"},
    )
    harness.update_relation_data(
        rel.id,  # type: ignore
        f"{mongodb_name}/2",
        {"database-address": "172.31.47.55"},
    )

    peer_addresses = [
        "10.0.0.1/24",
        "172.31.15.253",
        "172.31.24.68",
        "172.31.47.55",
    ]
    assert harness.charm.operator.state.local_auth_restrictions == [
        {"clientSource": ["127.0.0.1"], "serverAddress": ["127.0.0.1"]},
        {"clientSource": peer_addresses, "serverAddress": peer_addresses},
    ]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_config_server_local_auth_restrictions_include_shard_hosts(
    harness: Harness[MongoTestCharm], mongodb_name: str
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    with harness.hooks_disabled():
        relation_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")
        harness.update_relation_data(
            relation_id,
            "shard0",
            {"rs-hosts": '["172.31.20.165", "172.31.4.251"]'},
        )

    assert harness.charm.operator.state.local_auth_restrictions == [
        {"clientSource": ["127.0.0.1"], "serverAddress": ["127.0.0.1"]},
        {
            "clientSource": ["10.0.0.1/24", "172.31.20.165", "172.31.4.251"],
            "serverAddress": ["10.0.0.1/24", "172.31.20.165", "172.31.4.251"],
        },
    ]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_shard_local_auth_restrictions_include_config_server_hosts(
    harness: Harness[MongoTestCharm], mongodb_name: str
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    with harness.hooks_disabled():
        relation_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")
        harness.update_relation_data(
            relation_id,
            "config-server",
            {"host": '["172.31.14.77", "172.31.34.113"]'},
        )

    assert harness.charm.operator.state.local_auth_restrictions == [
        {"clientSource": ["127.0.0.1"], "serverAddress": ["127.0.0.1"]},
        {
            "clientSource": ["10.0.0.1/24", "172.31.14.77", "172.31.34.113"],
            "serverAddress": ["10.0.0.1/24", "172.31.14.77", "172.31.34.113"],
        },
    ]


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_config_server_local_auth_restrictions_empty_on_k8s(
    harness: Harness[MongoTestCharm], mongodb_name: str
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    with harness.hooks_disabled():
        relation_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")
        harness.update_relation_data(
            relation_id,
            "shard0",
            {"rs-hosts": '["shard0-0.shard0-endpoints", "shard0-1.shard0-endpoints"]'},
        )

    assert harness.charm.operator.state.local_auth_restrictions == []


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_shard_local_auth_restrictions_empty_on_k8s(
    harness: Harness[MongoTestCharm], mongodb_name: str
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    with harness.hooks_disabled():
        relation_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")
        harness.update_relation_data(
            relation_id,
            "config-server",
            {
                "host": '["config-server-0.config-server-endpoints", '
                '"config-server-1.config-server-endpoints"]'
            },
        )

    assert harness.charm.operator.state.local_auth_restrictions == []


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
    state.shard_state.config_server_replset = "config-server"

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

    if substrate == Substrate.lxd:
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

    if substrate == Substrate.lxd:
        assert state.get_cluster_id() == "1234"
    else:
        assert state.get_cluster_id() is None


def test_state_cluster_id_mongos_is_none(mongos_harness: Harness[MongosTestCharm], mongodb_name):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.db_initialised = True
    state = mongos_harness.charm.operator.state
    state.remove_cluster_id()

    assert state.get_cluster_id() is None


def test_entity_and_user_relations_split(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    entity_id = harness.add_relation("database", "entity-app")
    user_id = harness.add_relation("database", "user-app")
    harness.update_relation_data(entity_id, "entity-app", {"database": "d", "entity-type": "GROUP"})
    harness.update_relation_data(user_id, "user-app", {"database": "d"})
    state = harness.charm.operator.state
    entity_rel = harness.model.get_relation("database", entity_id)
    user_rel = harness.model.get_relation("database", user_id)

    assert state.is_entity_relation(entity_rel)
    assert not state.is_entity_relation(user_rel)
    assert state.entity_relations == {entity_rel}
    assert state.user_relations == {user_rel}


def test_entity_relations_on_config_server_are_cluster_relations(
    harness: Harness[MongoTestCharm],
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    request = {"database": "d", "entity-type": "GROUP"}
    cluster_id = harness.add_relation("cluster", "mongos")
    harness.add_relation_unit(cluster_id, "mongos/0")
    harness.update_relation_data(cluster_id, "mongos", request)
    # The client relation of this subordinate mongos is gone, and so are its units.
    gone_id = harness.add_relation("cluster", "gone-mongos")
    harness.update_relation_data(gone_id, "gone-mongos", request)
    db_id = harness.add_relation("database", "client-app")
    harness.update_relation_data(db_id, "client-app", {"database": "d", "entity-type": "GROUP"})
    state = harness.charm.operator.state
    cluster_rel = harness.model.get_relation("cluster", cluster_id)

    assert state.entity_relations == {cluster_rel}
    assert state.is_entity_relation(cluster_rel)
    assert not state.is_entity_relation(harness.model.get_relation("cluster", gone_id))


def test_entity_relations_on_shard_are_empty(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    with harness.hooks_disabled():
        db_id = harness.add_relation("database", "client-app")
        harness.update_relation_data(db_id, "client-app", {"database": "d", "entity-type": "GROUP"})
    state = harness.charm.operator.state

    # A shard refuses the database relation: it serves no entity request.
    assert state.is_entity_relation(harness.model.get_relation("database", db_id))
    assert state.entity_relations == set()


def test_managed_entities_roundtrip(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    peer = harness.charm.operator.state.app_peer_data
    assert peer.managed_entities == {}

    peer.managed_entities = {7: GROUP_DN}

    assert peer.managed_entities == {7: GROUP_DN}
    rel = harness.model.get_relation(PeerRelationNames.PEERS.value)
    wire = harness.get_relation_data(rel.id, harness.charm.app.name)  # type: ignore
    assert json.loads(wire["managed-entities-key"]) == {"7": GROUP_DN}


def test_orphaned_entity_ids(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    request = {"entity-type": "GROUP"}
    with harness.hooks_disabled():
        client_id = harness.add_relation(RelationNames.DATABASE.value, "client-app")
        cluster_id = harness.add_relation(RelationNames.CLUSTER.value, "mongos")
        harness.add_relation_unit(cluster_id, "mongos/0")
        harness.update_relation_data(cluster_id, "mongos", request)
        unitless_id = harness.add_relation(RelationNames.CLUSTER.value, "gone-mongos")
        harness.update_relation_data(unitless_id, "gone-mongos", request)
        cleared_id = harness.add_relation(RelationNames.CLUSTER.value, "cleared-mongos")
        harness.add_relation_unit(cleared_id, "cleared-mongos/0")
    state = harness.charm.operator.state
    state.app_peer_data.managed_entities = {
        client_id: "a",
        cluster_id: "b",
        unitless_id: "c",
        cleared_id: "d",
        999: "e",
    }

    # A live client relation keeps its role whatever it carries now, a cluster relation only
    # while it has units and requests it; a gone relation does not.
    assert state.orphaned_entity_ids == {unitless_id, cleared_id, 999}
    assert {relation.id for relation in state.entity_relations} == {cluster_id}


def test_cluster_state_entity_request_fields(mongos_harness: Harness[MongosTestCharm]):
    mongos_harness.set_leader(True)
    rel_id = mongos_harness.add_relation("cluster", "mongodb")
    state = mongos_harness.charm.operator.state.cluster

    assert state.entity_type == ""
    assert state.extra_group_roles == ""
    assert state.entity_permissions == ""
    assert state.requested_entity_name == ""
    assert state.entity_name == ""

    state.entity_type = "GROUP"
    state.extra_group_roles = "default"
    state.entity_permissions = "[]"
    state.requested_entity_name = GROUP_DN

    def data() -> dict[str, str]:
        return dict(mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name))

    # The data_interfaces names; the name in a secret of the mongos granted to the config-server.
    assert data()["entity-type"] == "GROUP"
    assert data()["extra-group-roles"] == "default"
    assert data()["entity-permissions"] == "[]"
    secret_id = data()["requested-entity-secret"]
    assert mongos_harness.get_secret_grants(secret_id, rel_id) == {"mongodb"}
    assert mongos_harness.model.get_secret(id=secret_id).get_content() == {"entity-name": GROUP_DN}
    assert state.entity_type == "GROUP"
    assert state.requested_entity_name == GROUP_DN

    # Another name gets another secret: the new id tells the config-server.
    state.requested_entity_name = "ou=villains"
    new_secret_id = data()["requested-entity-secret"]
    assert new_secret_id != secret_id
    assert state.requested_entity_name == "ou=villains"
    with pytest.raises(SecretNotFoundError):
        mongos_harness.model.get_secret(id=secret_id)

    state.requested_entity_name = ""
    assert "requested-entity-secret" not in data()
    assert state.requested_entity_name == ""
    with pytest.raises(SecretNotFoundError):
        mongos_harness.model.get_secret(id=new_secret_id)

    mongos_harness.update_relation_data(rel_id, "mongodb", {"entity-name": "x"})
    assert mongos_harness.charm.operator.state.cluster.entity_name == "x"


def test_cluster_state_seen_request(mongos_harness: Harness[MongosTestCharm]):
    mongos_harness.set_leader(True)
    rel_id = mongos_harness.add_relation("cluster", "mongodb")
    state = mongos_harness.charm.operator.state.cluster
    assert state.seen_request == {}

    # The library of the config-server keeps what it last processed under `data`.
    mongos_harness.update_relation_data(
        rel_id, "mongodb", {"data": json.dumps({"entity-type": "GROUP"})}
    )

    assert state.seen_request == {"entity-type": "GROUP"}
