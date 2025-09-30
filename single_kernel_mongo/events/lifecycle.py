#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Events handler for lifecycle events.

In charge of handling the lifecycle events such as install, start, pebble ready, etc.

The idea for the separation between event handlers and managers is the following:
 * Event Handlers call managers which are aware of the workload and state, and
 handle the different situations.
 * The Managers can raise exceptions during hook checks or while running the handler.
 * The event handler reacts to those errors to know if they should defer or
 not, or handle the return value of the manager in case it's an event.
 * The `defer` function should only be called in event handlers so we keep
 track of what is deferred and why.

This logic helps knowing and tracking the deferrals and also avoid the hidden defers.

Note: `update-status` events should never be deferred. They are recommended to
run every 5 minutes which is sufficient and deferring `update-status` can lead
to nasty behaviors on other events, especially the stop events on Kubernetes.
"""

import logging

from ops.charm import (
    ConfigChangedEvent,
    InstallEvent,
    LeaderElectedEvent,
    RelationChangedEvent,
    RelationDepartedEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
    StartEvent,
    StopEvent,
    StorageAttachedEvent,
    StorageDetachingEvent,
    UpdateStatusEvent,
)
from ops.framework import Object
from ops.pebble import ChangeError
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import CharmKind, Substrates
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import (
    CharmStatuses,
    LdapStatuses,
    MongoDBStatuses,
)
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    InvalidConfigRoleError,
    InvalidLdapQueryTemplateError,
    InvalidLdapUserToDnMappingError,
    UpgradeInProgressError,
    WaitingForLeaderError,
    WorkloadNotReadyError,
    WorkloadServiceError,
)
from single_kernel_mongo.utils.mongo_connection import NotReadyError

logger = logging.getLogger(__name__)


class LifecycleEventsHandler(Object):
    """Events handler for lifecycle events.

    In charge of handling the lifecycle events such as install, start, pebble ready, etc.
    """

    def __init__(self, dependent: OperatorProtocol, rel_name: PeerRelationNames):
        super().__init__(parent=dependent, key=dependent.name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.relation_name = rel_name

        self.framework.observe(getattr(self.charm.on, "install"), self.on_install)
        self.framework.observe(getattr(self.charm.on, "start"), self.on_start)
        self.framework.observe(getattr(self.charm.on, "stop"), self.on_stop)
        self.framework.observe(getattr(self.charm.on, "leader_elected"), self.on_leader_elected)

        if self.charm.substrate == Substrates.K8S:
            self.framework.observe(
                getattr(self.charm.on, f"{dependent.name}_pebble_ready"),
                self.on_start,
            )

        self.framework.observe(getattr(self.charm.on, "config_changed"), self.on_config_changed)
        self.framework.observe(getattr(self.charm.on, "update_status"), self.on_update_status)
        self.framework.observe(getattr(self.charm.on, "secret_changed"), self.on_secret_changed)

        self.framework.observe(
            self.charm.on[rel_name.value].relation_joined, self.on_relation_joined
        )
        self.framework.observe(
            self.charm.on[rel_name.value].relation_changed, self.on_relation_changed
        )
        self.framework.observe(
            self.charm.on[rel_name.value].relation_departed, self.on_relation_departed
        )

        if self.dependent.name == CharmKind.MONGOD:
            self.framework.observe(
                getattr(self.charm.on, "mongodb_storage_attached"),
                self.on_storage_attached,
            )
            self.framework.observe(
                getattr(self.charm.on, "mongodb_storage_detaching"),
                self.on_storage_detaching,
            )

        if self.charm.substrate == Substrates.VM and self.dependent.name == CharmKind.MONGOD:
            self.framework.observe(getattr(self.charm.on, "remove"), self.on_remove)

    def on_start(self, event: StartEvent):
        """Start event."""
        try:
            self.dependent.prepare_for_startup()
        except (ContainerNotReadyError, WorkloadServiceError):
            logger.info("Not ready to start.")
            event.defer()
            return
        except InvalidConfigRoleError:
            logger.info("Missing a valid role.")
            event.defer()
            return
        except WorkloadNotReadyError:
            logger.info("Still starting service.")
            self.dependent.state.statuses.add(
                MongoDBStatuses.WAITING_FOR_MONGODB_START.value,
                scope="unit",
                component=self.dependent.name,
            )
            event.defer()
            return
        except Exception as e:
            logger.error(f"Deferring because of {e.__class__.__name__} {e}")
            self.dependent.state.statuses.add(
                CharmStatuses.FAILED_SERVICES_START.value,
                scope="unit",
                component=self.dependent.name,
            )
            event.defer()
            return

    def on_stop(self, event: StopEvent):
        """Stop event."""
        self.dependent.prepare_for_shutdown()

    def on_install(self, event: InstallEvent):
        """Install event."""
        try:
            self.dependent.install_workloads()
        except (ContainerNotReadyError, WorkloadServiceError):
            logger.info("Not ready to start.")
            event.defer()
            return

    def on_leader_elected(self, event: LeaderElectedEvent):
        """Leader elected event."""
        self.dependent.new_leader()

    def on_config_changed(self, event: ConfigChangedEvent):
        """Config Changed Event."""
        try:
            self.dependent.update_config_and_restart()
        except (UpgradeInProgressError, WaitingForLeaderError):
            event.defer()
        except InvalidConfigRoleError:
            logger.info("Invalid config role.")
            if self.charm.unit.is_leader():
                self.dependent.state.statuses.add(
                    MongoDBStatuses.INVALID_ROLE.value,
                    scope="app",
                    component=self.dependent.name,
                )
            event.defer()
            return
        except InvalidLdapUserToDnMappingError:
            self.dependent.state.statuses.add(
                LdapStatuses.INVALID_LDAP_USER_MAPPING.value,
                scope="unit",
                component=self.dependent.name,
            )
        except InvalidLdapQueryTemplateError:
            self.dependent.state.statuses.add(
                LdapStatuses.INVALID_LDAP_QUERY_TEMPLATE.value,
                scope="unit",
                component=self.dependent.name,
            )

    def on_update_status(self, event: UpdateStatusEvent):
        """Update Status Event."""
        self.dependent.update_status()

    def on_secret_changed(self, event: SecretChangedEvent):
        """Secret changed event."""
        try:
            self.dependent.update_secrets_and_restart(
                secret_label=event.secret.label or "",
                secret_id=event.secret.id or "",
            )
        except (WorkloadServiceError, ChangeError) as err:
            logger.info("Failed to restart services", err, exc_info=True)
            self.dependent.state.statuses.add(
                CharmStatuses.FAILED_SERVICES_START.value,
                scope="unit",
                component=self.dependent.name,
            )
            event.defer()
            return

    def on_relation_joined(self, event: RelationJoinedEvent):
        """Relation joined event."""
        try:
            self.dependent.new_peer()
        except UpgradeInProgressError:
            logger.info(f"Deferring {event}: Upgrade in progress.")
            event.defer()
            return
        except (NotReadyError, PyMongoError, WorkloadServiceError):
            logger.info(f"Deferring {event}: Not ready yet.")
            event.defer()
            return

    def on_relation_changed(self, event: RelationChangedEvent):
        """Relation changed event."""
        try:
            self.dependent.peer_changed()
        except UpgradeInProgressError:
            logger.info(f"Deferring {event}: Upgrade in progress.")
            event.defer()
            return
        except (NotReadyError, PyMongoError, WorkloadServiceError):
            logger.info(f"Deferring {event}: Not ready yet.")
            event.defer()
            return

    def on_relation_departed(self, event: RelationDepartedEvent):
        """Relation departed event."""
        try:
            self.dependent.peer_leaving(departing_unit=event.departing_unit)
        except (NotReadyError, PyMongoError):
            logger.info(f"Deferring {event}: Not ready yet.")
            event.defer()
            return

    def on_storage_attached(self, event: StorageAttachedEvent):
        """Storage Attached Event."""
        self.dependent.prepare_storage()

    def on_storage_detaching(self, event: StorageDetachingEvent):
        """Storage Detaching Event."""
        self.dependent.prepare_storage_for_shutdown()

    def on_remove(self, _):
        """For MongoD VM, remove sysctl config."""
        self.dependent.sysctl_config.remove()  # type: ignore[attr-defined]
