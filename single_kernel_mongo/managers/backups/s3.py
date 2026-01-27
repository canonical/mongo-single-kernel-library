#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The S3 backup manager.

In this class, we manage the S3 specific code for backups.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, NewType, final, override

import boto3
from botocore.client import Config as BotoConfig
from botocore.exceptions import ClientError, ConnectTimeoutError, SSLError
from mypy_boto3_s3.service_resource import Bucket
from ops import Container, Relation
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from single_kernel_mongo.config.literals import (
    TRUST_STORE_PATH,
    Substrates,
    TrustStoreFiles,
)
from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.config.statuses import MongoDBStatuses
from single_kernel_mongo.exceptions import (
    FailedToCreateBucketError,
    InvalidStorageCredentialsError,
)
from single_kernel_mongo.managers.backups.common import CommonBackupManager
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import (
        MongoDBOperator,
    )  # pragma: nocover

BackupListType = NewType("BackupListType", list[tuple[str, str, str]])

GCS_PBM_OPTION_MAP = {
    "bucket": "storage.gcs.bucket",
    "path": "storage.gcs.prefix",
    "access-key": "storage.gcs.credentials.hmacAccessKey",
    "secret-key": "storage.gcs.credentials.hmacSecret",
}

logger = logging.getLogger(__name__)


@final
class S3BackupManager(CommonBackupManager):
    """Manager for the S3 integrator and backups."""

    invalid_integration_status = MongoDBStatuses.INVALID_S3_REL.value

    CONFIG_MAP = {
        "region": "storage.s3.region",
        "bucket": "storage.s3.bucket",
        "path": "storage.s3.prefix",
        "access-key": "storage.s3.credentials.access-key-id",
        "secret-key": "storage.s3.credentials.secret-access-key",
        "endpoint": "storage.s3.endpointUrl",
        "storage-class": "storage.s3.storageClass",
    }
    BASIC_CONFIG = {"storage.type": "s3"}
    backend = "s3"

    def __init__(
        self,
        dependent: MongoDBOperator,
        role: CharmSpec,
        substrate: Substrates,
        state: CharmState,
        container: Container | None,
    ) -> None:
        self.name = "backup-s3"
        super().__init__(dependent, role, substrate, state, container)

    @property
    @override
    def relation(self) -> Relation | None:
        return self.state.s3_relation

    def _get_bucket_resource(self, credentials: dict[str, str]) -> Bucket:
        """Get the Bucket resource from the s3 connection.

        Returns:
            Bucket: the s3 bucket for uploading/downloading backups
        """
        s3_resource = boto3.resource(
            "s3",
            region_name=credentials.get("region"),
            endpoint_url=credentials["endpoint"],
            aws_access_key_id=credentials["access-key"],
            aws_secret_access_key=credentials["secret-key"],
            config=BotoConfig(
                # https://github.com/boto/boto3/issues/4400#issuecomment-2600742103
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
            verify=(TRUST_STORE_PATH / TrustStoreFiles.PBM.value)
            if credentials.get("tls-ca-chain")
            else True,
        )

        return s3_resource.Bucket(credentials["bucket"])

    @retry(
        stop=stop_after_attempt(5),
        retry=retry_if_exception_type(ConnectTimeoutError),
        wait=wait_fixed(5),
        reraise=True,
    )
    @override
    def create_bucket(self, credentials: dict[str, str]) -> None:
        """Create bucket if it does not exist yet."""
        region = credentials.get("region")
        bucket_name = credentials["bucket"]

        if tls_ca_chain := credentials.get("tls-ca-chain", None):
            with open(TRUST_STORE_PATH / TrustStoreFiles.PBM.value, mode="w") as fd:
                # boto3 client will need the certificate on the node that runs the command
                fd.write("\n".join(tls_ca_chain))

        bucket = self._get_bucket_resource(credentials)

        try:
            bucket.meta.client.head_bucket(Bucket=bucket_name)
            logger.info(f"Using existing bucket {bucket_name}")
            return
        except ConnectTimeoutError as e:
            # Re-raise the error if the connection timeouts, so the user has the possibility to
            # fix network issues and call juju resolve to re-trigger the hook that calls
            # this method.
            logger.error(f"error: {e!s} - please fix the error and call juju resolve on this unit")
            raise e
        except ClientError:
            logger.warning("Bucket %s doesn't exist or you don't have access to it.", bucket_name)
        except SSLError as e:
            logger.error(f"error: {e!s} - Is TLS enabled and CA chain set on S3?")
            raise e

        try:
            # cf https://github.com/aws/aws-sdk-js/issues/3647, setting the
            # LocationConstraint to the default value of us-east-1 will fail
            if region and region != "us-east-1":
                bucket.create(CreateBucketConfiguration={"LocationConstraint": region})  # type: ignore
            else:
                bucket.create()
            bucket.wait_until_exists()
        except ClientError as e:
            if (
                "AccessDenied" in e.args[0]
                or "InvalidAccessKeyId" in e.args[0]
                or "SignatureDoesNotMatch" in e.args[0]
            ):
                logger.info("Incorrect credentials for S3")
                raise InvalidStorageCredentialsError
            logger.error(e)
            raise FailedToCreateBucketError from e

        logger.info(f"Bucket {bucket_name} is ready")

    @override
    def validate_config(self) -> bool:
        """Validates that the S3 config is complete."""
        if not self.relation:
            logger.info("No configuration for backups, no relation to S3 charm.")
            return False

        credentials = self.dependent.backup_events.credentials_for(self.relation)
        provided_configs = self.map_config_to_pbm_config(credentials)

        # Check on the origin dictionary so that we don't need to discriminate between gcs and s3
        if not credentials.get("access-key") or not credentials.get("secret-key"):
            logger.info("Missing s3 credentials")
            return False

        # note this is more of a sanity check - the s3 lib defaults this to the relation name
        if not credentials.get("bucket"):
            logger.info("Missing bucket")
            return False

        if provided_configs.get("storage.type") == "s3" and not provided_configs.get(
            "storage.s3.region"
        ):
            logger.info("Missing region - this is required for AWS")

        if provided_configs.get("storage.type") == "s3" and not provided_configs.get(
            "storage.s3.endpointUrl"
        ):
            logger.info("Missing S3 endpoint.")
            return False

        return True

    def _gcs_obsolecte_map(self, credentials: dict[str, str]) -> dict[str, str]:
        """This methods maintains the backward compatibility for HMAC based GCP authentication.

        This can still happen for now through the s3 integrator for already integrated clients.
        When PBM completely disables that support, it will be removed.
        """
        return {"storage.type": "gcs"} | {
            GCS_PBM_OPTION_MAP[s3_option]: s3_value
            for s3_option, s3_value in credentials.items()
            if GCS_PBM_OPTION_MAP.get(s3_option)
        }

    @override
    def map_config_to_pbm_config(self, credentials: dict[str, str]) -> dict[str, str]:
        if "googleapis" in credentials.get("endpoint", ""):
            return self._gcs_obsolecte_map(credentials)
        return super().map_config_to_pbm_config(credentials)
