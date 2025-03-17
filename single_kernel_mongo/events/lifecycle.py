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
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import CharmKind, Substrates
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    InvalidLdapQueryTemplateError,
    InvalidLdapUserToDnMappingError,
    UpgradeInProgressError,
    WaitingForLeaderError,
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
                getattr(self.charm.on, f"{dependent.name.value}_pebble_ready"), self.on_start
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
                getattr(self.charm.on, "mongodb_storage_attached"), self.on_storage_attached
            )
            self.framework.observe(
                getattr(self.charm.on, "mongodb_storage_detaching"), self.on_storage_detaching
            )

        if self.charm.substrate == Substrates.VM and self.dependent.name == CharmKind.MONGOD:
            self.framework.observe(getattr(self.charm.on, "remove"), self.on_remove)

    def on_start(self, event: StartEvent):
        """Start event."""
        try:
            self.dependent.on_start()
        except Exception as e:
            logger.error(f"Deferring because of {e.__class__.__name__} {e}")
            event.defer()
            return

    def on_stop(self, event: StopEvent):
        """Stop event."""
        self.dependent.on_stop()

    def on_install(self, event: InstallEvent):
        """Install event."""
        try:
            self.dependent.on_install()
        except (ContainerNotReadyError, WorkloadServiceError):
            logger.info("Not ready to start.")
            event.defer()
            return

    def on_leader_elected(self, event: LeaderElectedEvent):
        """Leader elected event."""
        self.dependent.on_leader_elected()

    def on_config_changed(self, event: ConfigChangedEvent):
        """Config Changed Event."""
        try:
            self.dependent.on_config_changed()
        except (UpgradeInProgressError, WaitingForLeaderError):
            event.defer()
            return
        except (InvalidLdapUserToDnMappingError, InvalidLdapQueryTemplateError) as err:
            self.charm.status_manager.to_blocked(f"{err}")
            return

    def on_update_status(self, event: UpdateStatusEvent):
        """Update Status Event."""
        try:
            self.dependent.on_update_status()
        except Exception:
            return

    def on_secret_changed(self, event: SecretChangedEvent):
        """Secret changed event."""
        self.dependent.on_secret_changed(
            secret_label=event.secret.label or "",
            secret_id=event.secret.id or "",
        )

    def on_relation_joined(self, event: RelationJoinedEvent):
        """Relation joined event."""
        try:
            self.dependent.on_relation_joined()
        except UpgradeInProgressError:
            event.defer()
            return
        except (NotReadyError, PyMongoError):
            event.defer()
            return

    def on_relation_changed(self, event: RelationChangedEvent):
        """Relation changed event."""
        try:
            self.dependent.on_relation_changed()
        except UpgradeInProgressError:
            event.defer()
            return
        except (NotReadyError, PyMongoError):
            event.defer()
            return

    def on_relation_departed(self, event: RelationDepartedEvent):
        """Relation departed event."""
        try:
            self.dependent.on_relation_departed(departing_unit=event.departing_unit)
        except (NotReadyError, PyMongoError):
            event.defer()
            return

    def on_storage_attached(self, event: StorageAttachedEvent):
        """Storage Attached Event."""
        self.dependent.on_storage_attached()

    def on_storage_detaching(self, event: StorageDetachingEvent):
        """Storage Detaching Event."""
        self.dependent.on_storage_detaching()

    def on_remove(self, _):
        """For MongoD VM, remove sysctl config."""
        self.dependent.sysctl_config.remove()  # type: ignore[attr-defined]
