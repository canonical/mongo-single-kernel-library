# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Explicit Scenario state builders for authentication tests."""

import json
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from ops.testing import Container, PeerRelation, Relation, RelationBase, Secret, State

from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles


def base_state(
    containers: Iterable[Container],
    peer_endpoint: str,
    role: MongoDBRoles,
    leader: bool = True,
    initialised: bool = True,
    peer_data: Mapping[str, str] | None = None,
    relations: Iterable[RelationBase] = (),
    config: Mapping[str, str | int | float | bool] | None = None,
    peers_data: Mapping[int, Mapping[str, str]] | None = None,
) -> State:
    """Build the common MongoDB and router state with required peer relations."""
    return State(
        leader=leader,
        containers=containers,
        config=config or {},
        relations={
            PeerRelation(
                endpoint=peer_endpoint,
                peers_data=peers_data or {},
                local_app_data={
                    "role": role.value,
                    "db_initialised": json.dumps(initialised),
                    **(peer_data or {}),
                },
            ),
            PeerRelation(endpoint=PeerRelationNames.STATUS_PEERS.value),
            PeerRelation(endpoint=PeerRelationNames.LDAP_PEERS.value),
            PeerRelation(endpoint=PeerRelationNames.ROLLINGOPS_PEERS.value),
            *relations,
        },
    )


def mongo_state(
    containers: Iterable[Container],
    role: MongoDBRoles = MongoDBRoles.REPLICATION,
    leader: bool = True,
    initialised: bool = True,
    peer_data: Mapping[str, str] | None = None,
    relations: Iterable[RelationBase] = (),
    config: Mapping[str, str | int | float | bool] | None = None,
    peers_data: Mapping[int, Mapping[str, str]] | None = None,
) -> State:
    """Build MongoDB peer state for a single Scenario event."""
    return base_state(
        containers,
        peer_endpoint=PeerRelationNames.PEERS.value,
        role=role,
        leader=leader,
        initialised=initialised,
        peer_data=peer_data,
        relations=relations,
        config={"role": role.value, **(config or {})},
        peers_data=peers_data,
    )


def mongos_state(
    containers: Iterable[Container],
    leader: bool = True,
    initialised: bool = True,
    peer_data: Mapping[str, str] | None = None,
    relations: Iterable[RelationBase] = (),
    config: Mapping[str, str | int | float | bool] | None = None,
) -> State:
    """Build router peer state for a single Scenario event."""
    return base_state(
        {replace(container, name="mongos") for container in containers},
        peer_endpoint=PeerRelationNames.ROUTER_PEERS.value,
        role=MongoDBRoles.MONGOS,
        leader=leader,
        initialised=initialised,
        peer_data=peer_data,
        relations=relations,
        config=config,
    )


def get_relation(state: State, endpoint: str) -> RelationBase:
    """Get a relation by endpoint from a Scenario state."""
    return next(relation for relation in state.relations if relation.endpoint == endpoint)


def oauth_relation(
    issuer: str = "https://issuer.example",
    client_id: str | None = None,
    client_secret_id: str | None = None,
) -> Relation:
    """Build complete OAuth provider data."""
    return Relation(
        endpoint="oauth",
        remote_app_name="hydra",
        remote_app_data={
            "issuer_url": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "introspection_endpoint": f"{issuer}/introspect",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "jwks_endpoint": f"{issuer}/jwks",
            "scope": "openid",
            **({"client_id": client_id} if client_id is not None else {}),
            **({"client_secret_id": client_secret_id} if client_secret_id is not None else {}),
        },
    )


@pytest.fixture
def registered_oauth() -> tuple[Relation, Secret]:
    """Provide an OAuth relation with registered client credentials."""
    secret = Secret(tracked_content={"secret": "client-secret"})
    oauth = oauth_relation("https://new-issuer", client_id="client-id", client_secret_id=secret.id)
    return oauth, secret


@pytest.fixture
def config_server_relations() -> tuple[Relation, Relation, Relation]:
    """Provide two configured router relations and one pending relation."""
    return (
        Relation(
            endpoint="cluster", remote_app_name="mongos-one", remote_app_data={"database": "mongos"}
        ),
        Relation(
            endpoint="cluster", remote_app_name="mongos-two", remote_app_data={"database": "mongos"}
        ),
        Relation(endpoint="cluster", remote_app_name="pending"),
    )


@pytest.fixture
def mongos_oauth_restart(mongos_ctx, mocker):
    @contextmanager
    def run(state_in, event, current="{}"):
        with mongos_ctx(event, state_in) as scenario:
            operator = scenario.charm.operator
            cluster = operator.cluster_manager
            config = operator.config_manager
            mocker.patch.object(cluster, "assert_pass_hook_checks")
            mocker.patch.object(cluster, "share_credentials_to_clients")
            mocker.patch.object(cluster, "_set_ldap_user_to_dn")
            mocker.patch.object(cluster, "_set_cluster_id")
            mocker.patch.object(operator, "update_keyfile", return_value=False)
            mocker.patch.object(operator, "update_config_server_db", return_value=False)
            mocker.patch("pathlib.Path.unlink")
            request = mocker.patch.object(operator.rollingops_manager, "request_async_lock")
            mocker.patch.object(config.workload, "read", return_value=[current])
            mocker.patch.object(config.workload, "active", return_value=True)
            write = mocker.patch.object(config.workload, "write")
            restart = mocker.patch.object(config.workload, "restart")
            yield SimpleNamespace(
                scenario=scenario,
                cluster=cluster,
                config=config,
                request=request,
                write=write,
                restart=restart,
            )

    return run


@pytest.fixture
def mongos_cluster() -> Relation:
    return Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.1:27017",
        },
    )


@pytest.fixture
def shard_state(mongodb_container: Iterable[Container], initialised: bool, leader: bool) -> State:
    return mongo_state(
        mongodb_container, role=MongoDBRoles.SHARD, initialised=initialised, leader=leader
    )


@pytest.fixture
def mock_issuer_tls(mocker):
    """Mocks the issuer checks and expose the TLS context to connection tests."""
    context = mocker.patch("single_kernel_mongo.managers.oauth.ssl.create_default_context")

    def discovery_response(url, **kwargs):
        issuer = url.removesuffix("/.well-known/openid-configuration")
        response = mocker.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"issuer": issuer, "token_endpoint": f"{issuer}/token", "jwks_uri": f"{issuer}/jwks"}
        )
        return response

    request = mocker.patch(
        "single_kernel_mongo.managers.oauth.urlopen", side_effect=discovery_response
    )
    return SimpleNamespace(context=context, request=request)
