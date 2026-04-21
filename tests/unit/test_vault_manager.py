# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from collections.abc import Callable

import pytest
from ops import BlockedStatus, testing
from ops.testing import Container, Context, PeerRelation, Relation, Secret, State
from pytest_mock import MockerFixture

from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import MongodStatuses
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm

NONCE = "112171d490c19c2c261063f7a120af51"

VaultStateFull = tuple[PeerRelation, PeerRelation, Relation, State]


@pytest.fixture
def vault_state_full(mongodb_name: str, mongodb_container: Container | None) -> VaultStateFull:
    peer_relation = testing.PeerRelation(
        id=1,
        endpoint=PeerRelationNames.PEERS.value,
        local_app_data={
            "role": "replication",
            "enable-encryption-at-rest": "true",
        },
    )
    status_peers_relation = testing.PeerRelation(
        id=2, endpoint=PeerRelationNames.STATUS_PEERS.value
    )
    secret_credentials = Secret(
        tracked_content={"role-id": "roleid", "role-secret-id": "rolesecretid"}, owner="unit"
    )
    vault_relation = testing.Relation(
        id=3,
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
        containers=mongodb_container,
        secrets={
            Secret(
                tracked_content={"vault-nonce": NONCE},
                label=f"vault-kv.{mongodb_name}.unit",
                owner="unit",
            ),
            secret_credentials,
        },
        relations={peer_relation, status_peers_relation, vault_relation},
        leader=True,
    )
    return peer_relation, status_peers_relation, vault_relation, state_in


@pytest.fixture
def vault_state_flip_encryption(
    mongodb_name: str, mongodb_container: Container | None
) -> Callable[[bool], VaultStateFull]:  # noqa: F821
    def vault_state_for(enabled: bool) -> VaultStateFull:
        status_peers_relation = testing.PeerRelation(
            id=1, endpoint=PeerRelationNames.STATUS_PEERS.value
        )
        peer_relation = testing.PeerRelation(
            id=2,
            endpoint=PeerRelationNames.PEERS.value,
            local_app_data={
                "role": "replication",
                "enable-encryption-at-rest": json.dumps(enabled),
            },
        )
        vault_relation = testing.Relation(
            id=3,
            endpoint="vault-kv",
        )
        relations: set[Relation | PeerRelation] = {status_peers_relation, peer_relation}
        if not enabled:
            relations.add(vault_relation)
        state_in = testing.State(
            config={"role": "replication", "enable-encryption-at-rest": enabled},
            containers=mongodb_container,
            secrets={
                Secret(
                    tracked_content={"vault-nonce": NONCE},
                    label=f"vault-kv.{mongodb_name}.unit",
                    owner="unit",
                ),
            },
            relations=relations,
            leader=True,
        )
        return peer_relation, status_peers_relation, vault_relation, state_in

    return vault_state_for


@pytest.fixture
def vault_state_encryption(
    vault_state_flip_encryption: Callable[[bool], VaultStateFull],
) -> VaultStateFull:
    return vault_state_flip_encryption(True)


@pytest.fixture
def vault_state_no_encryption(
    vault_state_flip_encryption: Callable[[bool], VaultStateFull],
) -> VaultStateFull:
    return vault_state_flip_encryption(False)


def test_vault_create_nonce(
    mongodb_ctx: Context[MongoTestCharm],
    mongodb_name: str,
    mocker: MockerFixture,
    mongodb_container: Container | None,
):
    peer_relation = testing.PeerRelation(
        id=1,
        endpoint=PeerRelationNames.PEERS.value,
        local_app_data={},
    )
    state_in = testing.State(
        config={"role": "replication", "enable-encryption-at-rest": True},
        containers=mongodb_container,
        secrets={},
        relations={peer_relation},
        leader=True,
    )
    with mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install"):
        state_out = mongodb_ctx.run(mongodb_ctx.on.install(), state=state_in)

    secret_out = state_out.get_secret(label=f"vault-kv.{mongodb_name}.unit")
    assert len(secret_out.latest_content.get("vault-nonce", "")) == 32


def test_vault_manager_request_nonce(
    mongodb_ctx: Context[MongoTestCharm], mongodb_name: str, mongodb_container: Container | None
):
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
        containers=mongodb_container,
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
    mongodb_ctx: Context[MongoTestCharm], mongodb_name: str, mongodb_container: Container | None
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
        containers=mongodb_container,
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

    assert state_out.unit_status == BlockedStatus(
        "The vault-kv interface cannot be used with encryption at rest disabled."
    )
    assert state_out.app_status == BlockedStatus(
        "The vault-kv interface cannot be used with encryption at rest disabled."
    )


def test_vault_manager_ready(
    mongodb_ctx: Context[MongoTestCharm],
    mongodb_name: str,
    short_mock_fs_interactions,
    mocker: MockerFixture,
    vault_state_full: VaultStateFull,
):
    _, _, vault_relation, state_in = vault_state_full

    check_connectivity = mocker.patch(
        "single_kernel_mongo.managers.vault.VaultManager._check_connectivity", return_value=True
    )
    set_environment = mocker.patch(
        "single_kernel_mongo.managers.config.VaultConfigManager.set_environment"
    )
    configure_self_signed_certificates = mocker.patch(
        "single_kernel_mongo.managers.vault.VaultManager.configure_self_signed_certificates"
    )
    prepare_log_dir = mocker.patch(
        "single_kernel_mongo.managers.vault.VaultManager.prepare_log_dir"
    )

    state_out = mongodb_ctx.run(
        mongodb_ctx.on.relation_changed(relation=vault_relation), state=state_in
    )
    prepare_log_dir.assert_called()
    configure_self_signed_certificates.assert_called()
    check_connectivity.assert_called()
    set_environment.assert_called()

    unit_secret = state_out.get_secret(label=f"vault-kv.{mongodb_name}.unit")

    assert unit_secret.latest_content.get("vault-url") == "https://192.168.1.1:8200"
    assert unit_secret.latest_content.get("vault-secret-mount-point") == "mongodb-mongodb"
    assert unit_secret.latest_content.get("vault-cert") == "BBBBBBBBB"
    assert unit_secret.latest_content.get("vault-role-id") == "roleid"
    assert unit_secret.latest_content.get("vault-role-secret-id") == "rolesecretid"


def test_vault_manager_removed(
    mongodb_ctx: Context[MongoTestCharm],
    short_mock_fs_interactions,
    vault_state_full: VaultStateFull,
):
    _, _, vault_relation, state_in = vault_state_full
    state_out = mongodb_ctx.run(
        mongodb_ctx.on.relation_broken(relation=vault_relation), state=state_in
    )
    assert state_out.unit_status == BlockedStatus(
        "Must be integrated with vault to enable encryption at rest."
    )
    assert state_out.app_status == BlockedStatus(
        "Must be integrated with vault to enable encryption at rest."
    )


def test_update_status(
    mongodb_ctx: Context[MongoTestCharm],
    short_mock_fs_interactions,
    mocker: MockerFixture,
    vault_state_full: VaultStateFull,
):
    _, _, vault_relation, state_in = vault_state_full
    with mocker.patch(
        "single_kernel_mongo.managers.vault.VaultManager.get_egress_subnets",
        return_value=["192.0.3.0/25", "192.0.3.128/25", "192.0.3.0/32"],
    ):
        state_out = mongodb_ctx.run(mongodb_ctx.on.update_status(), state=state_in)

    vault_relation_out = state_out.get_relation(vault_relation.id)
    assert (
        vault_relation_out.local_unit_data.get("egress_subnet")
        == "192.0.3.0/25,192.0.3.128/25,192.0.3.0/32"
    )


def test_update_status_should_not_integrate(
    mongodb_ctx: Context[MongoTestCharm],
    vault_state_no_encryption: VaultStateFull,
    short_mock_fs_interactions,
    mocker: MockerFixture,
):
    peer_relation, _, _, state_in = vault_state_no_encryption

    peer_relation.local_app_data["db_initialised"] = "true"

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.get_statuses",
        return_value=[MongodStatuses.PRIMARY.value],
    )
    with (
        mocker.patch(
            "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.perform_self_healing"
        ),
    ):
        state_out = mongodb_ctx.run(mongodb_ctx.on.update_status(), state=state_in)

    assert state_out.unit_status == BlockedStatus(
        "The vault-kv interface cannot be used with encryption at rest disabled."
    )
    assert state_out.app_status == BlockedStatus(
        "The vault-kv interface cannot be used with encryption at rest disabled."
    )


def test_update_status_should_integrate(
    mongodb_ctx: Context[MongoTestCharm],
    vault_state_encryption: VaultStateFull,
    short_mock_fs_interactions,
):
    _, _, _, state_in = vault_state_encryption
    state_out = mongodb_ctx.run(mongodb_ctx.on.update_status(), state=state_in)

    assert state_out.unit_status == BlockedStatus(
        "Must be integrated with vault to enable encryption at rest."
    )
    assert state_out.app_status == BlockedStatus(
        "Must be integrated with vault to enable encryption at rest."
    )
