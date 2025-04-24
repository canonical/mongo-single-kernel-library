# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Placeholder for status handling."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from logging import getLogger
from typing import TYPE_CHECKING

from ops.framework import Object
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    ErrorStatus,
    MaintenanceStatus,
    StatusBase,
    WaitingStatus,
)
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

from single_kernel_mongo.config.literals import CharmKind
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.utils.mongo_error_codes import MongoErrorCodes

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm

logger = getLogger(__name__)


@dataclass(frozen=True)
class Statuses:
    """Dataclass storing the statuses."""

    mongodb: StatusBase
    shard: StatusBase | None = field(default=None)
    config_server: StatusBase | None = field(default=None)
    pbm: StatusBase | None = field(default=None)
    ldap: StatusBase | None = field(default=None)


class StatusManager(Object):
    """Status Manager."""

    def __init__(self, charm: AbstractMongoCharm):
        super().__init__(parent=charm, key="status")
        self.charm = charm
        self.operator = charm.operator
        self.state = charm.operator.state
        self.charm_kind = self.operator.name

    def set_and_share_status(self, status: StatusBase) -> None:
        """Sets the unit status."""
        self.charm.unit.status = status
        if self.state.is_role(MongoDBRoles.SHARD):
            self.state.share_status_with_config_server(status)

    def to_active(self, message: str | None = None) -> None:
        """Sets status to active."""
        if message is None:
            self.set_and_share_status(ActiveStatus())
            return
        self.set_and_share_status(ActiveStatus(message))

    def to_blocked(self, message: str):
        """Sets status to blocked."""
        self.set_and_share_status(BlockedStatus(message))

    def to_waiting(self, message: str):
        """Sets status to waiting."""
        self.set_and_share_status(WaitingStatus(message))

    def to_maintenance(self, message: str):
        """Sets status to maintenance."""
        self.set_and_share_status(MaintenanceStatus(message))

    def to_error(self, message: str):
        """Sets status to error."""
        self.set_and_share_status(ErrorStatus(message))

    def clear_status(self, status: StatusBase) -> None:
        """Clears a status if this is the provided status."""
        if self.charm.unit.status != status:
            logger.debug(
                f"cannot clear status {status}, unit is in status {self.charm.unit.status}"
            )
            return
        self.charm.unit.status = ActiveStatus()

    def get_statuses(self) -> Statuses:
        """Collects the statuses of all managers."""
        if self.operator.name == CharmKind.MONGOD:
            return Statuses(
                mongodb=self.operator.mongo_manager.get_status(),
                shard=self.operator.shard_manager.get_status(),
                config_server=self.operator.config_server_manager.get_status(),
                pbm=self.operator.backup_manager.get_status(),
                ldap=self.operator.ldap_manager.get_status(),
            )
        # Mongos case
        return Statuses(
            mongodb=self.operator.get_sanity_check_status() or ActiveStatus(),
            ldap=self.operator.ldap_manager.get_status(),
        )

    def prioritize_statuses(self, statuses: Statuses) -> StatusBase:
        """Prioritizes the statuses."""
        mongodb_status, shard_status, config_server_status, pbm_status, ldap_status = (
            statuses.mongodb,
            statuses.shard,
            statuses.config_server,
            statuses.pbm,
            statuses.ldap,
        )
        if not isinstance(mongodb_status, ActiveStatus):
            return mongodb_status

        if shard_status and not isinstance(shard_status, ActiveStatus):
            return shard_status

        if config_server_status and not isinstance(config_server_status, ActiveStatus):
            return config_server_status

        if ldap_status and not isinstance(ldap_status, ActiveStatus):
            return ldap_status

        if pbm_status and not isinstance(pbm_status, ActiveStatus):
            return pbm_status

        # if all statuses are active report mongodb status over sharding status
        # This is also always the case for mongos charms because the 3 final statuses are None.
        return mongodb_status

    def process_and_share_statuses(self) -> None:
        """Retrieves statuses from processes inside charm and shares the highest priority status.

        When a non-fatal error occurs while processing statuses, the error is processed and
        returned as a statuses.
        """
        # retrieve statuses of different services running on Charmed MongoDB
        deployment_mode = (
            "replica set" if self.state.is_role(MongoDBRoles.REPLICATION) else "cluster"
        )
        waiting_status = None
        try:
            statuses = self.get_statuses()
        except OperationFailure as e:
            if e.code in (MongoErrorCodes.UNAUTHORIZED, MongoErrorCodes.AUTHENTICATION_FAILED):
                waiting_status = f"Waiting to sync passwords across the {deployment_mode}"
            elif e.code == MongoErrorCodes.FAILED_TO_SATISFY_READ_PREFERENCE:
                waiting_status = f"Waiting to sync internal membership across the {deployment_mode}"
            else:
                raise
        except ServerSelectionTimeoutError:
            waiting_status = f"Waiting to sync internal membership across the {deployment_mode}"

        if waiting_status:
            self.set_and_share_status(WaitingStatus(waiting_status))
            return

        main_status = self.prioritize_statuses(statuses)
        logger.debug(f"Main status is {main_status}")

        logger.info(f"{' Charm Statuses ':=^40}")
        for key, value in asdict(statuses).items():
            if value:
                logger.info(f"* {key}: {value}")
        logger.info(f"{' End of charm statuses ':=^40}")

        self.set_and_share_status(main_status)
