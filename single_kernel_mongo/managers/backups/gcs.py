#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The GCS backup manager.

In this class, we manage the GCS specific code for backups.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import TYPE_CHECKING, final, override

from google.api_core.exceptions import Conflict, Forbidden, GoogleAPIError, NotFound
from google.cloud import storage
from ops import Container
from ops.model import Relation

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.config.statuses import MongoDBStatuses
from single_kernel_mongo.exceptions import FailedToCreateBucketError, InvalidStorageCredentialsError
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
    backend = "gcs"

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

    def get_gcs_client(self, service_account_json: str) -> storage.Client:
        """Build a GCS client from a service-account JSON string.

        Args:
            credentials: JSON string for a service account key.

        Returns:
            google.cloud.storage.Client: Authenticated GCS client.

        Raises:
            ValueError: If the input is empty or not valid JSON.
            GoogleAPIError: If the client cannot be created due to SDK errors.
        """
        if not service_account_json:
            raise ValueError("Missing GCS secret_key (service account JSON).")

        try:
            service_account = json.loads(service_account_json)
        except (TypeError, ValueError) as e:
            raise ValueError("GCS secret_key is not valid JSON.") from e

        client_kwargs: dict[str, str] = {}
        if project_id := service_account.get("project_id"):
            client_kwargs["project"] = project_id

        return storage.Client.from_service_account_info(service_account, **client_kwargs)

    def _create_bucket(self, client: storage.Client, bucket: storage.Bucket) -> None:
        """Create a GCS bucket.

        Args:
            client: Authenticated google-cloud-storage client.
            bucket: Bucket handle to create.

        Raises:
            Conflict: If the bucket name is already taken (GCS bucket names are global).
            Forbidden: If the service account lacks storage.buckets.create permission.
            GoogleAPIError: For other GCS API errors.
        """
        try:
            client.create_bucket(bucket)
            logger.info("Created GCS bucket %r.", bucket.name)
        except Conflict:
            # GCS bucket names are global, and conflict means that name already taken
            logger.error(
                "Bucket name conflict for %s; please use a unique bucket name.", bucket.name
            )
            raise
        except Forbidden:
            logger.error(
                "Bucket %r cannot be created (forbidden). Missing permissions",
                bucket.name,
                exc_info=True,
            )
            raise

    @override
    def create_bucket(self, credentials: dict[str, str]) -> None:
        """Create bucket for google cloud storage.

        Args:
            credentials: The config containing the service account and other necessary information.

        Returns:
            True if the service account can access the bucket (or create it if missing) and
            can write/delete an object in it; False otherwise.

        Behavior:
            - If the configured bucket does not exist, try to create it.
            - Verify access via write and delete a small dummy blob.
        """
        service_account_json = credentials["secret-key"]
        bucket_name = credentials["bucket"]

        try:
            client = self.get_gcs_client(service_account_json)
            bucket = client.bucket(bucket_name)

            # ensure bucket exists or create
            try:
                exists = bucket.exists()
            except Forbidden:
                # Some env return 403 for exists when the caller lacks storage.buckets.get.
                # In this case we best-effort try to create. But it may still fail
                # if bucket exists or permission is missing.
                logger.warning(
                    "GCS bucket existence check returned 403 for %r; attempting to create it.",
                    bucket_name,
                )
                exists = False

            if not exists:
                logger.warning("GCS bucket %r not found; attempting to create it.", bucket_name)
                try:
                    self._create_bucket(client, bucket)
                except (Conflict, Forbidden) as e:
                    # this is already logged in the helper
                    raise FailedToCreateBucketError from e

            # write/delete to validate RW access
            prefix = credentials.get("path", "").strip("/")
            probe_name = (
                f"{prefix}/.mongodb-verify-{uuid.uuid4().hex}"
                if prefix
                else f".mongodb-verify-{uuid.uuid4().hex}"
            )

            blob = bucket.blob(probe_name)
            blob.upload_from_string(b"mongodb-verify", content_type="text/plain")
            blob.delete()
            logger.info("GCS credential validation succeeded.")

        except (ValueError, TypeError, KeyError) as e:
            logger.error(
                "GCS credential validation failed: invalid credentials: %s", e, exc_info=True
            )
            raise InvalidStorageCredentialsError
        except Forbidden as e:
            logger.error(
                "GCS credential validation failed: forbidden (missing permissions). Error: %s",
                e,
                exc_info=True,
            )
            raise InvalidStorageCredentialsError
        except NotFound as e:
            logger.error(
                "GCS credential validation failed: not found (endpoint/resource mismatch). Error: %s",
                e,
                exc_info=True,
            )
            raise InvalidStorageCredentialsError
        except GoogleAPIError as e:
            logger.error("GCS credential validation failed: %s", e, exc_info=True)
            raise InvalidStorageCredentialsError

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
