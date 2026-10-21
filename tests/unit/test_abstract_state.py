# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from single_kernel_mongo.state.abstract_state import AbstractRelationState


def _make_state(mocker, initial: dict) -> AbstractRelationState:
    """Builds an AbstractRelationState backed by a plain dict.

    Bypasses the real data_interface/relation plumbing so `update()` can be
    tested in isolation.
    """
    relation = mocker.MagicMock()
    relation.id = 1
    state = AbstractRelationState(
        relation=relation,
        data_interface=mocker.MagicMock(),
        component=None,
    )
    state.relation_data = dict(initial)
    return state


def test_update_stores_falsy_but_non_none_values(mocker):
    """A field explicitly set to a falsy-but-not-None value must be stored.

    Regression test: this was the root cause of a shard's `shard-replset`
    relation field disappearing. `update()` deleted any field whose value was
    falsy under Python truthiness (`not value`), rather than only fields
    explicitly set to `None` as documented.
    """
    state = _make_state(mocker, {})

    state.update({"empty-string-field": ""})
    assert state.relation_data["empty-string-field"] == ""

    state.update({"zero-field": "0"})
    assert state.relation_data["zero-field"] == "0"

    state.update({"normal-field": "shard-two"})
    assert state.relation_data["normal-field"] == "shard-two"


def test_update_deletes_only_explicit_none_values(mocker):
    """Only a literal `None` value should delete an existing field."""
    state = _make_state(mocker, {"to-delete": "old-value", "to-keep": "value"})

    state.update({"to-delete": None})

    assert "to-delete" not in state.relation_data
    assert state.relation_data["to-keep"] == "value"


def test_update_overwrites_existing_value(mocker):
    state = _make_state(mocker, {"field": "old"})

    state.update({"field": "new"})

    assert state.relation_data["field"] == "new"
