# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from datetime import timedelta

import pytest
from charmlibs.interfaces.certificate_transfer import (
    CertificatesAvailableEvent,
    CertificatesRemovedEvent,
)
from charmlibs.interfaces.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.model import BlockedStatus
from ops.testing import Harness

from single_kernel_mongo.config.literals import TRUST_STORE_PATH, TrustStoreFiles
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    InvalidOAuthWithShardError,
    WorkloadServiceError,
)
from single_kernel_mongo.state.oauth_state import OAuthState
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.integration.helpers.types import Substrate


def make_certificate(common_name: str, ca: bool = True) -> str:
    """A self-signed CA certificate, or a leaf certificate signed by a fresh CA."""
    key = generate_private_key()
    ca_certificate = generate_ca(key, timedelta(days=1), common_name)
    if ca:
        return str(ca_certificate)
    csr = generate_csr(key, common_name)
    return str(generate_certificate(csr, ca_certificate, key, timedelta(days=1)))


CA_ONE = make_certificate("ca-one")
CA_TWO = make_certificate("ca-two")
LEAF = make_certificate("leaf", ca=False)
PRIVATE_KEY = str(generate_private_key())
CERTS_V1 = {"certificates": json.dumps([CA_ONE]), "version": "1"}
CHARM_COPY = TRUST_STORE_PATH / TrustStoreFiles.OAUTH.value


@pytest.fixture
def oauth_harness(harness: Harness[MongoTestCharm], mock_fs_interactions):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.app_peer_data.db_initialised = True
    return harness


def patch_workload(mocker, substrate: Substrate, method: str, **kwargs):
    """Patches a method of the workload class of this substrate."""
    workload = (
        "vm_workload.VMWorkload"
        if substrate == Substrate.lxd
        else "k8s_workload.KubernetesWorkload"
    )
    return mocker.patch(f"single_kernel_mongo.core.{workload}.{method}", **kwargs)


def add_certs(harness: Harness, data: dict | None = None) -> int:
    rel_id = harness.add_relation(ExternalRequirerRelations.OAUTH_CERT.value, "certs")
    harness.add_relation_unit(rel_id, "certs/0")
    harness.update_relation_data(rel_id, "certs", data if data is not None else CERTS_V1)
    return rel_id


@pytest.mark.parametrize(
    ("db_initialised", "role", "expected_error"),
    (
        (False, MongoDBRoles.REPLICATION, DeferrableFailedHookChecksError),
        (True, MongoDBRoles.SHARD, InvalidOAuthWithShardError),
    ),
)
def test_hook_checks_fail(
    oauth_harness: Harness[MongoTestCharm], db_initialised, role, expected_error
):
    oauth_harness.charm.operator.state.app_peer_data.db_initialised = db_initialised
    oauth_harness.charm.operator.state.app_peer_data.role = role
    add_certs(oauth_harness)
    with pytest.raises(expected_error):
        oauth_harness.charm.operator.oauth_manager.store_certificates({CA_ONE})
    assert oauth_harness.charm.operator.state.oauth.chain is None


def test_certificate_cycle(oauth_harness: Harness[MongoTestCharm], mocker, substrate):
    write = patch_workload(mocker, substrate, "write")
    patch_workload(mocker, substrate, "exists", return_value=True)
    delete = patch_workload(mocker, substrate, "delete")
    opened = mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("pathlib.Path.is_file", return_value=True)
    unlink = mocker.patch("pathlib.Path.unlink")
    bundle_file = oauth_harness.charm.operator.workload.paths.oauth_certificates_file

    # 1. The provider publishes its CA: chain stored, bundle and charm copy written.
    certs_id = add_certs(oauth_harness)
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_ONE]
    write.assert_called_with(bundle_file, CA_ONE)
    opened.assert_called_with(CHARM_COPY, mode="w")
    opened().write.assert_called_with(CA_ONE)

    # 2. The certificate set changes: both files are rewritten with the sorted chain.
    oauth_harness.update_relation_data(
        certs_id, "certs", {"certificates": json.dumps([CA_TWO, CA_ONE])}
    )
    chain = sorted([CA_ONE, CA_TWO])
    assert oauth_harness.charm.operator.state.oauth.chain == chain
    write.assert_called_with(bundle_file, "\n".join(chain))
    opened().write.assert_called_with("\n".join(chain))

    # 3. The CA relation is removed: the chain and both files are gone.
    delete.reset_mock()
    unlink.reset_mock()
    oauth_harness.remove_relation(certs_id)
    assert oauth_harness.charm.operator.state.oauth.chain is None
    delete.assert_called_once_with(bundle_file)
    unlink.assert_called_once()


def test_empty_certificate_set_removes_the_files(
    oauth_harness: Harness[MongoTestCharm], mocker, substrate
):
    # The provider withdraws its certificates while the relation stays.
    patch_workload(mocker, substrate, "exists", return_value=True)
    delete = patch_workload(mocker, substrate, "delete")
    mocker.patch("pathlib.Path.is_file", return_value=True)
    unlink = mocker.patch("pathlib.Path.unlink")
    certs_id = add_certs(oauth_harness)
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_ONE]
    delete.reset_mock()
    unlink.reset_mock()

    oauth_harness.update_relation_data(certs_id, "certs", {"certificates": json.dumps([])})
    assert oauth_harness.charm.operator.state.oauth.chain is None
    delete.assert_called_once_with(
        oauth_harness.charm.operator.workload.paths.oauth_certificates_file
    )
    unlink.assert_called_once()


def test_certificates_v0_provider_unsupported(oauth_harness: Harness[MongoTestCharm]):
    # charmlibs-interfaces-certificate-transfer 1.0.0's v0 fallback JSON-decodes the raw PEM
    # values and returns an empty set, so v0 providers are unsupported (v1 provider required).
    rel_id = oauth_harness.add_relation(ExternalRequirerRelations.OAUTH_CERT.value, "certs")
    oauth_harness.add_relation_unit(rel_id, "certs/0")
    oauth_harness.update_relation_data(
        rel_id,
        "certs/0",
        {"ca": "PEM-CA", "certificate": "PEM-CERT", "chain": json.dumps(["PEM-B", "PEM-A"])},
    )
    assert oauth_harness.charm.operator.state.oauth.chain is None


@pytest.mark.parametrize(
    ("role", "leader", "shared"),
    (
        (MongoDBRoles.CONFIG_SERVER, True, True),
        (MongoDBRoles.CONFIG_SERVER, False, False),
        (MongoDBRoles.REPLICATION, True, False),
    ),
)
def test_only_the_config_server_leader_shares_the_bundle(
    oauth_harness: Harness[MongoTestCharm], mocker, role, leader, shared
):
    share = mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterProvider.update_oauth_ca_to_mongos"
    )
    oauth_harness.charm.operator.state.app_peer_data.role = role
    oauth_harness.set_leader(leader)

    certs_id = add_certs(oauth_harness)
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_ONE]  # every unit keeps it
    assert share.called is shared

    share.reset_mock()
    oauth_harness.remove_relation(certs_id)
    assert share.called is shared


def test_shard_blocks_and_ignores_the_certificates(
    oauth_harness: Harness[MongoTestCharm], mocker, substrate
):
    write = patch_workload(mocker, substrate, "write")
    oauth_harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    manager = oauth_harness.charm.operator.oauth_manager
    shard_status = OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value

    certs_id = add_certs(oauth_harness)
    assert oauth_harness.charm.operator.state.oauth.chain is None
    bundle_file = oauth_harness.charm.operator.workload.paths.oauth_certificates_file
    assert bundle_file not in [call.args[0] for call in write.call_args_list]
    assert manager.get_statuses(scope="unit") == [shard_status]
    assert manager.get_statuses(scope="unit", recompute=True) == [shard_status]

    oauth_harness.remove_relation(certs_id)
    assert manager.get_statuses(scope="unit") == []


@pytest.mark.parametrize(
    "certificates",
    (
        ["not a certificate"],
        [PRIVATE_KEY],
        [CA_ONE[:200] + "\n-----END CERTIFICATE-----\n"],
        [CA_ONE, "not a certificate"],
    ),
    ids=("text", "private-key", "truncated", "one-of-two"),
)
def test_load_certificates_rejects(certificates):
    with pytest.raises(ValueError, match=f"of {len(certificates)}"):
        OAuthState.load_certificates(certificates)


def test_load_certificates_reads_every_certificate_of_an_entry():
    assert len(OAuthState.load_certificates([f"{CA_ONE}\n{CA_TWO}", LEAF])) == 3


def test_invalid_certificates_block_and_keep_the_last_chain(
    oauth_harness: Harness[MongoTestCharm], mocker, substrate
):
    write = patch_workload(mocker, substrate, "write")
    share = mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterProvider.update_oauth_ca_to_mongos"
    )
    oauth_harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    manager = oauth_harness.charm.operator.oauth_manager
    invalid = OAuthStatuses.INVALID_CERTS.value
    certs_id = add_certs(oauth_harness)
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_ONE]
    write.reset_mock()
    share.reset_mock()

    # The provider sends something that is not a certificate: nothing changes but the status.
    oauth_harness.update_relation_data(
        certs_id, "certs", {"certificates": json.dumps([CA_TWO, PRIVATE_KEY])}
    )
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_ONE]
    write.assert_not_called()
    share.assert_not_called()
    assert manager.get_statuses(scope="unit") == [invalid]
    # The status handler's recompute (update-status) keeps it while the data stays invalid.
    assert manager.get_statuses(scope="unit", recompute=True) == [invalid]
    oauth_harness.evaluate_status()
    assert oauth_harness.model.unit.status == as_status(invalid)
    assert isinstance(oauth_harness.model.unit.status, BlockedStatus)

    # A valid set again: stored, shared, status gone.
    oauth_harness.update_relation_data(certs_id, "certs", {"certificates": json.dumps([CA_TWO])})
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_TWO]
    write.assert_called_with(
        oauth_harness.charm.operator.workload.paths.oauth_certificates_file, CA_TWO
    )
    share.assert_called_once()
    assert manager.get_statuses(scope="unit") == []


def test_invalid_certificates_on_a_new_relation(
    oauth_harness: Harness[MongoTestCharm], mocker, substrate
):
    write = patch_workload(mocker, substrate, "write")
    manager = oauth_harness.charm.operator.oauth_manager
    certs_id = add_certs(oauth_harness, {"certificates": json.dumps(["garbage"]), "version": "1"})
    assert oauth_harness.charm.operator.state.oauth.chain is None
    bundle_file = oauth_harness.charm.operator.workload.paths.oauth_certificates_file
    assert bundle_file not in [call.args[0] for call in write.call_args_list]
    assert manager.get_statuses(scope="unit") == [OAuthStatuses.INVALID_CERTS.value]

    # Removing the relation clears the status.
    oauth_harness.remove_relation(certs_id)
    assert manager.get_statuses(scope="unit") == []
    assert manager.get_statuses(scope="unit", recompute=True) == []


def test_non_ca_certificate_is_stored_with_a_warning(
    oauth_harness: Harness[MongoTestCharm], caplog
):
    # A pinned server certificate is a valid trust anchor for mongod (libcurl accepts partial
    # chains), so it is only logged.
    caplog.set_level(logging.WARNING)
    add_certs(oauth_harness, {"certificates": json.dumps([LEAF]), "version": "1"})
    assert oauth_harness.charm.operator.state.oauth.chain == [LEAF]
    assert "CN=leaf" in caplog.text and "is not a CA certificate" in caplog.text
    assert oauth_harness.charm.operator.oauth_manager.get_statuses(scope="unit") == []


def test_deferred_certificate_event_is_dropped_once_the_relation_is_gone(
    oauth_harness: Harness[MongoTestCharm], mocker
):
    # A deferred certificate_set_updated re-run after certificates_removed must not restore
    # the stale chain.
    mocker.patch("pathlib.Path.is_file", return_value=False)
    defer = mocker.spy(CertificatesAvailableEvent, "defer")
    oauth_harness.charm.operator.state.app_peer_data.db_initialised = False  # hook checks defer
    certs_id = add_certs(oauth_harness)
    assert defer.call_count == 1
    oauth_harness.remove_relation(certs_id)

    oauth_harness.charm.operator.state.app_peer_data.db_initialised = True
    oauth_harness.framework.reemit()
    assert defer.call_count == 1  # not deferred again
    assert oauth_harness.charm.operator.state.oauth.chain is None


def test_certificate_event_defers_on_workload_error(
    oauth_harness: Harness[MongoTestCharm], mocker, substrate
):
    # On K8s, writing the bundle fails while pebble is unreachable: defer, do not error the hook.
    patch_workload(mocker, substrate, "write", side_effect=WorkloadServiceError("unreachable"))
    defer = mocker.spy(CertificatesAvailableEvent, "defer")
    add_certs(oauth_harness)
    defer.assert_called_once()


def test_certificates_removed_defers_on_workload_error(
    oauth_harness: Harness[MongoTestCharm], mocker, substrate
):
    certs_id = add_certs(oauth_harness)
    patch_workload(mocker, substrate, "exists", side_effect=WorkloadServiceError("unreachable"))
    defer = mocker.spy(CertificatesRemovedEvent, "defer")
    oauth_harness.remove_relation(certs_id)
    defer.assert_called_once()
    assert oauth_harness.charm.operator.state.oauth.chain is None


@pytest.fixture
def update_status(oauth_harness: Harness[MongoTestCharm], mocker):
    """Emits update-status; the operator's own update-status handler is not under test."""
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_status")
    return oauth_harness.charm.on.update_status.emit


def test_update_status_stores_the_certificates_of_a_lost_event(
    oauth_harness: Harness[MongoTestCharm], update_status, mocker, substrate
):
    write = patch_workload(mocker, substrate, "write")
    add_certs(oauth_harness)
    # The unit missed the event that brought CA_ONE: it still holds an older chain.
    oauth_harness.charm.operator.state.oauth.chain = [CA_TWO]
    write.reset_mock()

    update_status()
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_ONE]
    write.assert_called_with(
        oauth_harness.charm.operator.workload.paths.oauth_certificates_file, CA_ONE
    )


def test_update_status_removes_the_certificates_of_a_removed_relation(
    oauth_harness: Harness[MongoTestCharm], update_status, mocker, substrate
):
    patch_workload(mocker, substrate, "exists", return_value=True)
    delete = patch_workload(mocker, substrate, "delete")
    mocker.patch("pathlib.Path.is_file", return_value=False)
    # The unit missed certificates-removed: it still holds a chain without a relation.
    oauth_harness.charm.operator.state.oauth.chain = [CA_ONE]

    update_status()
    assert oauth_harness.charm.operator.state.oauth.chain is None
    delete.assert_called_once_with(
        oauth_harness.charm.operator.workload.paths.oauth_certificates_file
    )


@pytest.mark.parametrize(("leader", "shared"), ((True, True), (False, False)))
def test_update_status_in_sync_only_shares_the_bundle_again(
    oauth_harness: Harness[MongoTestCharm], update_status, mocker, substrate, leader, shared
):
    share = mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterProvider.update_oauth_ca_to_mongos"
    )
    oauth_harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    add_certs(oauth_harness)
    oauth_harness.set_leader(leader)
    write = patch_workload(mocker, substrate, "write")
    secret_set = mocker.spy(SecretCache, "set")
    share.reset_mock()

    update_status()
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_ONE]
    write.assert_not_called()
    secret_set.assert_not_called()
    assert share.called is shared


def test_update_status_waits_for_the_database(
    oauth_harness: Harness[MongoTestCharm], update_status, caplog
):
    add_certs(oauth_harness)
    oauth_harness.charm.operator.state.oauth.chain = [CA_TWO]
    oauth_harness.charm.operator.state.app_peer_data.db_initialised = False
    caplog.set_level(logging.WARNING)

    update_status()
    assert oauth_harness.charm.operator.state.oauth.chain == [CA_TWO]
    assert "could not reconcile" not in caplog.text  # no warning on every update-status


def test_update_status_logs_what_it_cannot_reconcile(
    oauth_harness: Harness[MongoTestCharm], update_status, mocker, substrate, caplog
):
    add_certs(oauth_harness)
    oauth_harness.charm.operator.state.oauth.chain = [CA_TWO]
    patch_workload(mocker, substrate, "write", side_effect=WorkloadServiceError("unreachable"))
    caplog.set_level(logging.WARNING)

    update_status()  # does not raise
    assert "could not reconcile the OAuth CA certificates" in caplog.text


@pytest.mark.parametrize(
    ("role", "certificates"),
    ((MongoDBRoles.SHARD, [CA_ONE]), (MongoDBRoles.REPLICATION, ["garbage"])),
    ids=("shard", "invalid-pem"),
)
def test_update_status_skips_a_set_it_would_refuse(
    oauth_harness: Harness[MongoTestCharm], update_status, mocker, caplog, role, certificates
):
    oauth_harness.charm.operator.state.app_peer_data.role = role
    add_certs(oauth_harness, {"certificates": json.dumps(certificates), "version": "1"})
    store = mocker.spy(type(oauth_harness.charm.operator.oauth_manager), "store_certificates")
    caplog.set_level(logging.WARNING)
    caplog.clear()  # the relation event already logged why

    update_status()
    store.assert_not_called()
    assert oauth_harness.charm.operator.state.oauth.chain is None
    # The Blocked status already tells why.
    assert not [r for r in caplog.records if r.name.startswith("single_kernel_mongo")]
