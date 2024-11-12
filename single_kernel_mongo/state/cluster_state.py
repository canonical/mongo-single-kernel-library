#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Cluster state."""


class ClusterState:
    """The stored state for the TLS relation."""

    @property
    def config_server_url(self) -> str:
        """Is TLS enabled."""
        return ""
