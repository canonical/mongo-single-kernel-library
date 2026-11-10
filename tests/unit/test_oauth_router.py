# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
from ops.testing import Harness

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.state.oauth_state import OAuthStateKeys
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.unit.test_oauth_manager import patch_workload


@pytest.fixture
def router(mongos_harness: Harness[MongosTestCharm], mocker, mock_fs_interactions):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.db_initialised = True
    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.read", return_value=data)
    mocker.patch("single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read", return_value=data)
    rel_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.add_relation_unit(rel_id, "mongodb/0")
    mongos_harness.update_relation_data(
        rel_id,
        "mongodb",
        {"key-file": "deadbeef", "config-server-db": "mongodb/2.2.2.2:27017"},
    )
    return mongos_harness, rel_id


def test_router_copies_the_bundle(router, mocker, substrate):
    harness, rel_id = router
    write = patch_workload(mocker, substrate, "write")

    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": "PEM"})
    harness.charm.operator.cluster_manager._set_oauth_ca_bundle()

    assert harness.charm.operator.state.oauth.chain == ["PEM"]
    write.assert_any_call(harness.charm.operator.workload.paths.oauth_certificates_file, "PEM")


def test_router_reads_plain_bundle(router):
    # A cluster relation created before this revision never requested `oauth-ca-secret` as a
    # secret; the library then writes it in plain data.
    harness, rel_id = router
    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": "PLAIN-PEM"})
    assert harness.charm.operator.state.cluster.oauth_ca_bundle == "PLAIN-PEM"


def test_router_reads_plain_bundle_next_to_relation_secrets(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, monkeypatch
):
    # With Juju secrets on: the keyfile travels in the relation secret while the bundle of a
    # relation that never requested it as a secret arrives in plain data.
    monkeypatch.setenv("JUJU_VERSION", "3.6.0")  # Harness defaults to 0.0.0: no secrets.
    harness = mongos_harness
    harness.set_leader(True)
    rel_id = harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    harness.add_relation_unit(rel_id, "mongodb/0")
    secret_id = harness.add_model_secret(
        "mongodb", {"key-file": "deadbeef", "config-server-db": "mongodb/2.2.2.2:27017"}
    )
    harness.grant_secret(secret_id, harness.charm.app.name)
    harness.update_relation_data(
        rel_id, "mongodb", {"secret-extra": secret_id, "oauth-ca-secret": "PLAIN-PEM"}
    )
    assert harness.charm.operator.state.cluster.keyfile == "deadbeef"

    harness.charm.operator.cluster_manager._set_oauth_ca_bundle()
    assert harness.charm.operator.state.oauth.chain == ["PLAIN-PEM"]


def test_router_clears_when_the_config_server_removes_the_bundle(router, mocker, substrate):
    harness, rel_id = router
    patch_workload(mocker, substrate, "exists", return_value=True)
    delete = patch_workload(mocker, substrate, "delete")

    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": "PEM"})
    harness.charm.operator.cluster_manager._set_oauth_ca_bundle()
    assert harness.charm.operator.state.oauth.chain == ["PEM"]

    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": ""})
    harness.charm.operator.cluster_manager._set_oauth_ca_bundle()
    assert harness.charm.operator.state.oauth.chain is None
    delete.assert_called_with(harness.charm.operator.workload.paths.oauth_certificates_file)


def test_router_bundle_copy_is_idempotent(router, mocker, substrate, caplog):
    # Every router restart copies the bundle: the chain secret changes only with the bundle,
    # the bundle file is rewritten each time.
    harness, rel_id = router
    write = patch_workload(mocker, substrate, "write")
    secret_set = mocker.spy(SecretCache, "set")
    secret_remove = mocker.spy(SecretCache, "remove")
    cluster_manager = harness.charm.operator.cluster_manager
    bundle_file = harness.charm.operator.workload.paths.oauth_certificates_file

    def chain_calls(spy) -> int:
        return sum(OAuthStateKeys.CHAIN.value in call.args for call in spy.call_args_list)

    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": "PEM"})
    for _ in range(3):
        cluster_manager._set_oauth_ca_bundle()
    assert harness.charm.operator.state.oauth.chain == ["PEM"]
    assert chain_calls(secret_set) == 1
    assert [call.args[0] for call in write.call_args_list].count(bundle_file) == 3

    caplog.set_level(logging.ERROR)
    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": ""})
    for _ in range(3):
        cluster_manager._set_oauth_ca_bundle()
    assert harness.charm.operator.state.oauth.chain is None
    assert chain_calls(secret_remove) == 1
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]


@pytest.mark.parametrize("db_initialised", (False, True))
def test_router_start_and_restart_copy_the_bundle(router, mocker, substrate, db_initialised):
    # Both the first start and later restarts copy the bundle from the cluster relation.
    harness, rel_id = router
    harness.charm.operator.state.db_initialised = db_initialised
    write = patch_workload(mocker, substrate, "write")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs")
    harness.update_relation_data(
        rel_id,
        "mongodb",
        {
            "username": "charmed-operator",
            "password": "password",  # nosec: B105
            "oauth-ca-secret": "PEM",
        },
    )
    assert harness.charm.operator.state.oauth.chain is None

    harness.charm.operator.cluster_manager.update_mongos_and_restart()

    assert harness.charm.operator.state.oauth.chain == ["PEM"]
    write.assert_any_call(harness.charm.operator.workload.paths.oauth_certificates_file, "PEM")


def test_router_writes_no_charm_ca_copy(router, mocker, substrate):
    # The bundle goes to the workload only, never to the trust-anchor directory (on VM, the
    # client application's machine).
    harness, rel_id = router
    write = patch_workload(mocker, substrate, "write")
    patch_workload(mocker, substrate, "exists", return_value=True)
    delete = patch_workload(mocker, substrate, "delete")
    opened = mocker.patch("builtins.open")
    is_file = mocker.patch("pathlib.Path.is_file", return_value=True)
    unlink = mocker.patch("pathlib.Path.unlink")
    bundle_file = harness.charm.operator.workload.paths.oauth_certificates_file

    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": "PEM"})
    harness.charm.operator.cluster_manager._set_oauth_ca_bundle()
    write.assert_any_call(bundle_file, "PEM")
    opened.assert_not_called()

    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": ""})
    harness.charm.operator.cluster_manager._set_oauth_ca_bundle()
    delete.assert_called_with(bundle_file)
    is_file.assert_not_called()
    unlink.assert_not_called()


def test_router_has_no_oauth_relation_and_no_status(router):
    harness, rel_id = router
    manager = harness.charm.operator.oauth_manager
    assert manager.certificate_transfer is None
    harness.update_relation_data(rel_id, "mongodb", {"oauth-ca-secret": "PEM"})
    harness.charm.operator.cluster_manager._set_oauth_ca_bundle()
    assert manager.get_statuses(scope="unit", recompute=True) == []
