# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from ops import BlockedStatus, testing
from ops.testing import Context, Secret

from single_kernel_mongo.config.relations import PeerRelationNames
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm

NONCE = "112171d490c19c2c261063f7a120af51"


def test_vault_manager_request_nonce(mongodb_ctx: Context[MongoTestCharm], mongodb_name: str):
    peer_relation = testing.PeerRelation(
        id=1,
        endpoint=PeerRelationNames.PEERS.value,
        local_app_data={
            "role": "replication",
            "enable-encryption-at-rest": "true",
        },
    )
    vault_relation = testing.Relation(
        id=2,
        endpoint="vault-kv",
    )
    state_in = testing.State(
        config={"role": "replication", "enable-encryption-at-rest": True},
        secrets={
            Secret(
                tracked_content={"vault-nonce": NONCE},
                label=f"vault-kv.{mongodb_name}.unit",
                owner="unit",
            )
        },
        relations={peer_relation, vault_relation},
        leader=True,
    )

    state_out = mongodb_ctx.run(
        mongodb_ctx.on.relation_joined(relation=vault_relation), state=state_in
    )

    vault_relation_after = state_out.get_relation(vault_relation.id)
    assert vault_relation_after.local_app_data["mount_suffix"] == mongodb_name
    assert vault_relation_after.local_unit_data["nonce"] == NONCE
    assert vault_relation_after.local_unit_data["egress_subnet"]


def test_vault_manager_no_encryption_status(
    mongodb_ctx: Context[MongoTestCharm], mongodb_name: str
):
    status_peers_relation = testing.PeerRelation(
        id=1, endpoint=PeerRelationNames.STATUS_PEERS.value
    )
    peer_relation = testing.PeerRelation(
        id=2,
        endpoint=PeerRelationNames.PEERS.value,
        local_app_data={
            "role": "replication",
            "enable-encryption-at-rest": "false",
        },
    )
    vault_relation = testing.Relation(
        id=3,
        endpoint="vault-kv",
    )
    state_in = testing.State(
        config={"role": "replication", "enable-encryption-at-rest": False},
        secrets={
            Secret(
                tracked_content={"vault-nonce": NONCE},
                label=f"vault-kv.{mongodb_name}.unit",
                owner="unit",
            )
        },
        relations={status_peers_relation, peer_relation, vault_relation},
        leader=True,
    )
    state_out = mongodb_ctx.run(
        mongodb_ctx.on.relation_joined(relation=vault_relation), state=state_in
    )

    assert state_out.unit_status == BlockedStatus("Can't integrate with vault.")
    assert state_out.app_status == BlockedStatus("Can't integrate with vault.")


def test_vault_manager_ready(
    mongodb_ctx: Context[MongoTestCharm], mongodb_name: str, short_mock_fs_interactions, mocker
):
    peer_relation = testing.PeerRelation(
        id=1,
        endpoint=PeerRelationNames.PEERS.value,
        local_app_data={
            "role": "replication",
            "enable-encryption-at-rest": "true",
        },
    )
    secret_credentials = Secret(
        tracked_content={"role-id": "roleid", "role-secret-id": "rolesecretid"}, owner="unit"
    )
    vault_relation = testing.Relation(
        id=2,
        endpoint="vault-kv",
        local_app_data={
            "mount_suffix": mongodb_name,
        },
        local_unit_data={
            "nonce": NONCE,
            "egress_subnet": "192.0.2.0/25,192.0.2.128/25,192.0.2.0/32",
        },
        remote_app_data={
            "vault_url": "https://192.168.1.1:8200",
            "mount": "mongodb-mongodb",
            "ca_certificate": "BBBBBBBBB",
            "credentials": f'{{"{NONCE}": "{secret_credentials.id}" }}',
        },
    )
    state_in = testing.State(
        config={"role": "replication", "enable-encryption-at-rest": True},
        secrets={
            Secret(
                tracked_content={"vault-nonce": NONCE},
                label=f"vault-kv.{mongodb_name}.unit",
                owner="unit",
            ),
            secret_credentials,
        },
        relations={peer_relation, vault_relation},
        leader=True,
    )

    check_connectivity = mocker.patch(
        "single_kernel_mongo.managers.vault.VaultManager._check_connectivity", return_value=True
    )
    set_environment = mocker.patch(
        "single_kernel_mongo.managers.config.VaultConfigManager.set_environment"
    )

    state_out = mongodb_ctx.run(
        mongodb_ctx.on.relation_changed(relation=vault_relation), state=state_in
    )
    check_connectivity.assert_called()
    set_environment.assert_called()

    unit_secret = state_out.get_secret(label=f"vault-kv.{mongodb_name}.unit")
    app_secret = state_out.get_secret(label=f"vault-kv.{mongodb_name}.app")

    assert app_secret.latest_content.get("vault-url") == "https://192.168.1.1:8200"
    assert app_secret.latest_content.get("vault-secret-mount-point") == "mongodb-mongodb"
    assert app_secret.latest_content.get("vault-cert") == "BBBBBBBBB"
    assert unit_secret.latest_content.get("vault-role-id") == "roleid"
    assert unit_secret.latest_content.get("vault-role-secret-id") == "rolesecretid"
