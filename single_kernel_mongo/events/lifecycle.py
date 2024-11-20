#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Events handler for lifecycle events.

In charge of handling the lifecycle events such as install, start, pebble ready, etc.
"""

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

from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    UpgradeInProgressError,
    WorkloadServiceError,
)


class LifecycleEventsHandler(Object):
    """Events handler for lifecycle events.

    In charge of handling the lifecycle events such as install, start, pebble ready, etc.
    """

    def __init__(self, dependent: OperatorProtocol, rel_name: str):
        super().__init__(parent=dependent, key=dependent.name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.relation_name = rel_name

        self.framework.observe(getattr(self.charm.on, "install"), self.on_install)
        self.framework.observe(getattr(self.charm.on, "start"), self.on_start)
        self.framework.observe(getattr(self.charm.on, "stop"), self.on_stop)
        self.framework.observe(getattr(self.charm.on, "leader_elected"), self.on_leader_elected)

        if self.charm.substrate == "k8s":
            self.framework.observe(getattr(self.charm.on, "mongod_pebble_ready"), self.on_start)

        self.framework.observe(getattr(self.charm.on, "config_changed"), self.on_config_changed)
        self.framework.observe(getattr(self.charm.on, "update_status"), self.on_update_status)
        self.framework.observe(getattr(self.charm.on, "secret_changed"), self.on_secret_changed)

        self.framework.observe(self.charm.on[rel_name].relation_joined, self.on_relation_joined)
        self.framework.observe(self.charm.on[rel_name].relation_changed, self.on_relation_changed)
        self.framework.observe(self.charm.on[rel_name].relation_departed, self.on_relation_departed)

        self.framework.observe(
            getattr(self.charm.on, "mongodb_storage_attached"), self.on_storage_attached
        )
        self.framework.observe(
            getattr(self.charm.on, "mongodb_storage_detaching"), self.on_storage_detaching
        )

    def on_start(self, event: StartEvent):
        """Start event."""
        try:
            self.dependent.on_start()
        except Exception:
            event.defer()
            return

    def on_stop(self, event: StopEvent):
        """Stop event."""
        ...

    def on_install(self, event: InstallEvent):
        """Install event."""
        try:
            self.dependent.on_install()
        except (ContainerNotReadyError, WorkloadServiceError):
            event.defer()
            return

    def on_leader_elected(self, event: LeaderElectedEvent):
        """Leader elected event."""
        self.dependent.on_leader_elected()

    def on_config_changed(self, event: ConfigChangedEvent):
        """Config Changed Event."""
        try:
            self.dependent.on_config_changed()
        except UpgradeInProgressError:
            event.defer()
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

    def on_relation_changed(self, event: RelationChangedEvent):
        """Relation changed event."""
        try:
            self.dependent.on_relation_changed()
        except UpgradeInProgressError:
            event.defer()
            return

    def on_relation_departed(self, event: RelationDepartedEvent):
        """Relation departed event."""
        self.dependent.on_relation_departed(departing_unit=event.departing_unit)

    def on_storage_attached(self, event: StorageAttachedEvent):
        """Storage Attached Event."""
        self.dependent.on_storage_attached()

    def on_storage_detaching(self, event: StorageDetachingEvent):
        """Storage Detaching Event."""
        self.dependent.on_storage_detaching()
