# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from single_kernel_mongo.config.statuses import EntityStatuses


def test_invalid_request_status():
    status = EntityStatuses.invalid_request("entity-type 'USER' is not supported, only GROUP")
    assert status.code == 5001
    assert status.is_fatal
    assert status.message == (
        "invalid or unsupported request: entity-type 'USER' is not supported, only GROUP"
    )
    assert "remove and re-add" in status.resolution


def test_mongodb_refused_status():
    status = EntityStatuses.mongodb_refused("Role already exists")
    assert status.code == 5002
    assert status.is_fatal
    assert status.message == "MongoDB refused createRole: Role already exists"


def test_rejected_blocked_status():
    blocked = EntityStatuses.rejected("MongoDB refused createRole: Role already exists", 7)
    assert blocked.status == "blocked"
    assert blocked.message == "MongoDB refused createRole: Role already exists (relation 7)"
