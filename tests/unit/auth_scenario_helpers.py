# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Explicit Scenario state builders for authentication tests."""

import json
from dataclasses import replace

from ops.testing import PeerRelation, Relation, State

from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles


def authentication_state(
    containers,
    *,
    peer_endpoint,
    role,
    leader=True,
    initialised=True,
    peer_data=None,
    relations=(),
    config=None,
):
    """Provide the peer relations needed by the operators and status framework."""
    return State(
        leader=leader,
        containers=containers,
        config=config or {},
        relations={
            PeerRelation(
                endpoint=peer_endpoint,
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


def mongo_state(containers, *, role=MongoDBRoles.REPLICATION, **kwargs):
    """Build MongoDB peer state for a single Scenario event."""
    return authentication_state(
        containers,
        peer_endpoint=PeerRelationNames.PEERS.value,
        role=role,
        config={"role": role.value, **kwargs.pop("config", {})},
        **kwargs,
    )


def mongos_state(containers, **kwargs):
    """Build router state without a direct OAuth relation."""
    return authentication_state(
        {replace(container, name="mongos") for container in containers},
        peer_endpoint=PeerRelationNames.ROUTER_PEERS.value,
        role=MongoDBRoles.MONGOS,
        **kwargs,
    )


def get_relation(state, endpoint):
    """Get a relation by endpoint from a Scenario state."""
    return next(relation for relation in state.relations if relation.endpoint == endpoint)


def oauth_relation(issuer="https://issuer.example", **kwargs):
    """Build complete OAuth provider data without needing a client secret."""
    return Relation(
        endpoint="oauth",
        remote_app_name="hydra",
        remote_app_data={
            "issuer_url": issuer,
            "client_id": "client-id",
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "introspection_endpoint": f"{issuer}/introspect",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "jwks_endpoint": f"{issuer}/jwks",
            "scope": "openid",
            **kwargs,
        },
    )
