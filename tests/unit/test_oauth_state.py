# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.secrets import SecretCache
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm


def test_chain_is_a_unit_secret(harness: Harness[MongoTestCharm]):
    state = harness.charm.operator.state
    assert state.oauth.chain is None
    state.oauth.chain = ["PEM-TWO", "PEM-ONE"]
    assert state.oauth.chain == ["PEM-ONE", "PEM-TWO"]
    # Unit scope: the value lives in the unit secret, not in the app secret.
    assert state.oauth.secrets.get_for_key(Scope.UNIT, "oauth-chain") is not None
    assert state.oauth.secrets.get_for_key(Scope.APP, "oauth-chain") is None
    state.oauth.chain = None
    assert state.oauth.chain is None


def test_same_chain_creates_no_secret_revision(harness: Harness[MongoTestCharm], mocker):
    state = harness.charm.operator.state
    state.oauth.chain = ["PEM-ONE", "PEM-TWO"]
    secret_set = mocker.spy(SecretCache, "set")
    secret_remove = mocker.spy(SecretCache, "remove")

    state.oauth.chain = ["PEM-TWO", "PEM-ONE"]
    secret_set.assert_not_called()
    state.oauth.chain = None
    state.oauth.chain = []
    assert secret_remove.call_count == 1


def test_bundle(harness: Harness[MongoTestCharm]):
    state = harness.charm.operator.state
    assert state.oauth.bundle is None
    state.oauth.chain = ["PEM-TWO", "PEM-ONE"]
    assert state.oauth.bundle == "PEM-ONE\nPEM-TWO"
    # Routers store the bundle they received as a one-entry chain.
    state.oauth.bundle = "PEM-BUNDLE"
    assert state.oauth.chain == ["PEM-BUNDLE"]
    state.oauth.bundle = None
    assert state.oauth.chain is None


def test_relation_accessors(harness: Harness[MongoTestCharm]):
    state = harness.charm.operator.state
    assert state.oauth_cert_relation is None
    assert state.oauth_peer_relation is not None
    harness.add_relation(ExternalRequirerRelations.OAUTH_CERT.value, "self-signed-certificates")
    assert state.oauth_cert_relation is not None
