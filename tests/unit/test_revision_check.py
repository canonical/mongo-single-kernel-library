# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import pytest
from data_platform_helpers.version_check import DEPLOYMENT_TYPE, VERSION_CONST, NoVersionError
from ops.testing import Harness

from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm

CHARMHUB_DEPLOYMENT = "ch"
LOCAL_DEPLOYMENT = "local"
RELATION_TO_CHECK_VERSION = "sharding"
CHARM_VERSION = "123"
VALID_VERSION = CHARM_VERSION
INVALID_VERSION = "456"

APP_0 = "app_zero"
APP_1 = "app_one"
APP_2 = "app_two"


def add_invalid_relation(harness: Harness[MongoTestCharm], deployment: str):
    rel_id = harness.add_relation(RELATION_TO_CHECK_VERSION, APP_0)
    harness.add_relation_unit(rel_id, f"{APP_0}/0")
    harness.update_relation_data(
        rel_id,
        f"{APP_0}",
        {VERSION_CONST: INVALID_VERSION, DEPLOYMENT_TYPE: deployment},
    )


def add_valid_relation(harness: Harness[MongoTestCharm], deployment: str):
    rel_id = harness.add_relation(RELATION_TO_CHECK_VERSION, APP_1)
    harness.add_relation_unit(rel_id, f"{APP_1}/0")
    harness.update_relation_data(
        rel_id,
        f"{APP_1}",
        {VERSION_CONST: VALID_VERSION, DEPLOYMENT_TYPE: deployment},
    )


def add_relation_with_no_version(harness: Harness[MongoTestCharm]):
    rel_id = harness.add_relation(RELATION_TO_CHECK_VERSION, RELATION_TO_CHECK_VERSION)
    harness.add_relation_unit(rel_id, f"{APP_2}/0")


def test_get_invalid_relation(harness: Harness[MongoTestCharm], mocker):
    harness.charm.operator.cross_app_version_checker.version = CHARM_VERSION

    mocker.patch(
        "single_kernel_mongo.state.config_server_state.AppShardingComponentState.has_received_credentials",
        return_value=True,
    )

    add_invalid_relation(harness, deployment=LOCAL_DEPLOYMENT)
    add_valid_relation(harness, deployment=LOCAL_DEPLOYMENT)
    invalid_version = harness.charm.operator.cross_app_version_checker.get_invalid_versions()
    assert invalid_version == [(APP_0, INVALID_VERSION)]
    # case two: missing version info
    add_relation_with_no_version(harness)
    with pytest.raises(NoVersionError):
        harness.charm.operator.cross_app_version_checker.get_invalid_versions()


def test_get_version_of_related_app(harness: Harness[MongoTestCharm], mocker):
    harness.charm.operator.cross_app_version_checker.version = CHARM_VERSION
    add_invalid_relation(harness, deployment=LOCAL_DEPLOYMENT)
    version = harness.charm.operator.cross_app_version_checker.get_version_of_related_app(APP_0)
    assert version == INVALID_VERSION

    # case two: missing version info
    add_relation_with_no_version(harness)
    with pytest.raises(NoVersionError):
        harness.charm.operator.cross_app_version_checker.get_version_of_related_app(APP_2)


def test_is_related_app_locally_built_charm(harness: Harness[MongoTestCharm], mocker):
    """Verifies that version checker can retrieve integrated application deployment types."""
    harness.charm.operator.cross_app_version_checker.version = CHARM_VERSION
    # case one: local deployment
    add_valid_relation(harness, deployment=LOCAL_DEPLOYMENT)
    assert harness.charm.operator.cross_app_version_checker.is_local_charm(APP_1)

    # case two: charmhub deployment
    add_invalid_relation(harness, deployment=CHARMHUB_DEPLOYMENT)
    assert not harness.charm.operator.cross_app_version_checker.is_local_charm(APP_0)

    # case three: missing version info
    add_relation_with_no_version(harness)
    with pytest.raises(NoVersionError):
        harness.charm.operator.cross_app_version_checker.is_local_charm(APP_2)
