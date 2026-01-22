#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The GCS backup manager.

In this class, we manage the GCS specific code for backups.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, final, override

from ops import Container
from ops.model import Relation

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.config.statuses import MongoDBStatuses
from single_kernel_mongo.managers.backups.common import CommonBackupManager
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import (
        MongoDBOperator,
    )  # pragma: nocover

logger = logging.getLogger(__name__)


@final
class GCSBackupManager(CommonBackupManager):
    """Manager for the S3 integrator and backups."""

    invalid_integration_status = MongoDBStatuses.INVALID_S3_REL.value
    CONFIG_MAP = {
        "bucket": "storage.gcs.bucket",
        "path": "storage.gcs.prefix",
        "clientEmail": "storage.gcs.credentials.clientEmail",
        "privateKey": "storage.gcs.credentials.privateKey",
    }
    BASIC_CONFIG = {"storage.type": "gcs"}

    def __init__(
        self,
        dependent: MongoDBOperator,
        role: CharmSpec,
        substrate: Substrates,
        state: CharmState,
        container: Container | None,
    ) -> None:
        self.name = "backup-gcs"
        super().__init__(dependent, role, substrate, state, container)

    @property
    @override
    def relation(self) -> Relation | None:
        return self.state.gcs_relation

    @override
    def create_bucket(self, credentials: dict[str, str]) -> None:
        pass

    @override
    def validate_config(self) -> bool:
        """Validates that the GCS config is complete."""
        if not self.relation:
            logger.info("No configuration for backups, no relation to GCS charm.")
            return False

        credentials = self.dependent.backup_events.credentials_for(self.relation)
        provided_configs = self.map_config_to_pbm_config(credentials)

        # Check on the origin dictionary so that we don't need to discriminate between gcs and s3
        if not credentials.get("access-key"):
            logger.info("Missing s3 credentials")
            return False
        if not credentials.get("bucket"):
            logger.info("Missing bucket")
            return False

        if not provided_configs.get("storage.gcs.credentials.clientEmail"):
            logger.info("Missing region - this is required for AWS")

        if not provided_configs.get("storage.gcs.credentials.privateKey"):
            logger.info("Missing S3 endpoint.")
            return False

        return True
