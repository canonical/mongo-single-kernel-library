#!/usr/bin/env python3
"""Code for handling the version checking in the cluster."""
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.version_check import NoVersionError, get_charm_revision

from single_kernel_mongo.config.statuses import ConfigServerStatuses, ShardStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


logger = logging.getLogger(__name__)


class VersionChecker:
    """Checks the version statuses and incompatibilities in the cluster."""

    def __init__(self, dependent: MongoDBOperator):
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = dependent.state
        self.version_checker = dependent.cross_app_version_checker

    def get_cluster_mismatched_revision_status(self) -> StatusObject | None:
        """Returns a Status if the cluster has mismatched revisions."""
        # check for invalid versions in sharding integrations, i.e. a shard running on
        # revision  88 and a config-server running on revision 110
        current_charms_version = get_charm_revision(
            self.charm.unit,
            local_version=self.dependent.workload.get_internal_revision(),
        )
        local_identifier = (
            "-locally built" if self.version_checker.is_local_charm(self.charm.app.name) else ""
        )
        try:
            # This part needs some explanation: If we are running this during
            # the pre-refresh hook that happens after the upgrade, we want to
            # check our version against the already upgraded config server, so
            # we use the current revision that stores the revision of the
            # former charm until the charm is fully upgraded.
            old_version = self.version_checker.version
            self.version_checker.version = self.state.unit_upgrade_peer_data.current_revision
            if self.version_checker.are_related_apps_valid():
                return None
        except NoVersionError as e:
            # relations to shards/config-server are expected to provide a version number. If they
            # do not, it is because they are from an earlier charm revision, i.e. pre-revison X.
            logger.debug(e)
            if self.state.is_role(MongoDBRoles.SHARD):
                return ShardStatuses.older_version_shard_needs_upgrade(
                    current_charms_version, local_identifier
                )

        finally:
            # Always restore the former version.
            self.version_checker.version = old_version

        if self.state.is_role(MongoDBRoles.SHARD):
            config_server_revision = self.version_checker.get_version_of_related_app(
                self.state.config_server_name
            )
            remote_local_identifier = (
                "-locally built"
                if self.version_checker.is_local_charm(self.state.config_server_name)
                else ""
            )
            return ShardStatuses.shard_needs_upgrade(
                current_charms_version,
                local_identifier,
                config_server_revision,
                remote_local_identifier,
            )

        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return ConfigServerStatuses.waiting_for_shard_upgrade(
                current_charms_version, local_identifier
            )

        return None
