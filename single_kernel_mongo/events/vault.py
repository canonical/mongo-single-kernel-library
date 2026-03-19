#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handlers for vault-kv relation."""

from __future__ import annotations

import json
from logging import getLogger
from typing import TYPE_CHECKING, final

from ops import (
    ActionEvent,
    ConfigChangedEvent,
    InstallEvent,
    LeaderElectedEvent,
    Object,
    UpdateStatusEvent,
)

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import VaultStatuses
from single_kernel_mongo.exceptions import (
    ImpossibleToRotateMasterKeyError,
    InvalidConfigError,
    WaitingForLeaderError,
)
from single_kernel_mongo.lib.charms.vault_k8s.v0 import vault_kv
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.structured_config import MongoDBCharmConfig
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


logger = getLogger(__name__)


@final
class VaultEventHandler(Object):
    """Event Handler for the vault relation and actions."""

    def __init__(self, dependent: MongoDBOperator):
        self.dependent: MongoDBOperator = dependent
        self.charm: AbstractMongoCharm[MongoDBCharmConfig, MongoDBOperator] = dependent.charm
        self.manager = dependent.vault_manager
        self.relation_name = ExternalRequirerRelations.VAULT.value

        super().__init__(parent=dependent, key=self.relation_name)
        self.interface = vault_kv.VaultKvRequires(self.charm, self.relation_name, self.charm.name)

        self.framework.observe(self.interface.on.connected, self._on_connected)
        self.framework.observe(self.interface.on.ready, self._on_ready)
        self.framework.observe(self.interface.on.gone_away, self._on_gone_away)

        # Handlers for lifecycle events for the vault specific parts.
        self.framework.observe(self.charm.on.install, self._generate_nonce)
        self.framework.observe(self.charm.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.charm.on.config_changed, self._on_config_changed)
        self.framework.observe(self.charm.on.update_status, self._on_update_status)

        # Action to rotate the master key
        self.framework.observe(
            getattr(self.charm.on, "rotate_encryption_master_key_action"),
            observer=self._on_rotate_master_key,
        )

    def _generate_nonce(self, event: InstallEvent):
        """Generates a nonce for that unit and store it."""
        self.manager.generate_nonce()

    def _on_connected(self, event: vault_kv.VaultKvConnectedEvent) -> None:
        """Handler for on connected event that requests for approle."""
        if not self.manager.assert_should_integrate():
            self.manager.set_status(VaultStatuses.VAULT_INTEGRATED.value, scope="both")
            return
        self.manager.clear_statuses(scope="both")
        egress_subnets = self.manager.get_subnets()
        nonce = self.manager.get_nonce()
        self.interface.request_credentials(
            event.relation, egress_subnet=egress_subnets, nonce=nonce
        )

    def _on_ready(self, event: vault_kv.VaultKvReadyEvent) -> None:
        """Handler for on ready event that starts vault."""
        if not self.manager.assert_should_integrate():
            self.manager.set_status(VaultStatuses.VAULT_INTEGRATED.value, scope="both")
            return
        self.manager.clear_statuses(scope="both")
        # First, get the credentials from the interface
        unit_credentials = self.interface.get_unit_credentials(event.relation)
        secret = self.model.get_secret(id=unit_credentials)
        secret_content = secret.get_content(refresh=True)
        data = vault_kv.VaultKvProviderSchema.model_validate(
            {
                "vault_url": self.interface.get_vault_url(event.relation),
                "mount": self.interface.get_mount(event.relation),
                "ca_certificate": self.interface.get_ca_certificate(event.relation),
                "credentials": json.dumps(
                    {
                        "role-id": secret_content["role-id"],
                        "role-secret-id": secret_content["role-secret-id"],
                    }
                ),
            }
        )
        self.manager.prepare_vault_agent(data)

    def _on_leader_elected(self, event: LeaderElectedEvent):
        """Handler for leader elected events that ensures that the config option is stored."""
        self.manager.ensures_config_stored()

    def _on_config_changed(self, event: ConfigChangedEvent):
        """Handler for config-changed events that ensures that the config option doesn't change."""
        try:
            self.manager.ensures_value_is_not_updated()
        except WaitingForLeaderError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
            return
        except InvalidConfigError:
            self.manager.set_status(VaultStatuses.INVALID_CONFIG.value, scope="both")
            return

    def _on_gone_away(self, event: vault_kv.VaultKvGoneAwayEvent) -> None:
        """Handler for the relation broken event."""
        if self.manager.assert_should_integrate():
            self.manager.set_status(VaultStatuses.VAULT_NOT_INTEGRATED.value, scope="both")
            return
        logger.info(
            f"[{event}]] Nothing to remove, we should not have integrated vault in the first place."
        )
        self.manager.state.statuses.clear(component=self.manager.name, scope="unit")
        if self.model.unit.is_leader():
            self.manager.state.statuses.clear(component=self.manager.name, scope="app")

    def _on_update_status(self, event: UpdateStatusEvent) -> None:
        """Handler for on connected event that requests for approle."""
        if not self.manager.assert_should_integrate():
            # No need for a status here, it will all be recomputed anyway.
            return
        if not self.manager.state.vault_relation:
            return
        egress_subnets = self.manager.get_subnets()
        nonce = self.manager.get_nonce()
        self.interface.request_credentials(
            self.manager.state.vault_relation,
            egress_subnet=egress_subnets,
            nonce=nonce,
        )

    def _on_rotate_master_key(self, event: ActionEvent):
        """Rotates the master key."""
        try:
            self.charm.status_handler.set_running_status(
                VaultStatuses.VAULT_ROTATE_MASTER_KEY.value, scope="unit"
            )
            self.manager.rotate_master_key()
            event.set_results({"result": "success", "message": "OK"})
        except ImpossibleToRotateMasterKeyError as e:
            event.set_results({"result": "failed", "message": f"{e}"})
            event.fail(f"Failed to rotate master key: {e}")
