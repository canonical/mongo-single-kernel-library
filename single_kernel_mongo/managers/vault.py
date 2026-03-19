# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The managers for the vault relations between vault and mongodb charms."""

from __future__ import annotations

import secrets
from logging import getLogger
from typing import TYPE_CHECKING, Literal, final, override

import hvac
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import ManagerStatusProtocol
from data_platform_helpers.advanced_statuses.types import Scope
from ops.framework import Object

from single_kernel_mongo.config.literals import TRUST_STORE_PATH, Substrates, TrustStoreFiles
from single_kernel_mongo.config.models import VaultConfigurationState
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import VaultStatuses
from single_kernel_mongo.exceptions import (
    ImpossibleToRotateMasterKeyError,
    InvalidConfigError,
    WaitingForLeaderError,
    WorkloadExecError,
)
from single_kernel_mongo.lib.charms.vault_k8s.v0 import vault_kv
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator

logger = getLogger(__name__)


@final
class VaultManager(Object, ManagerStatusProtocol):
    """Manager for the vault relation and workload."""

    state: CharmState

    def __init__(
        self,
        dependent: MongoDBOperator,
        state: CharmState,
        substrate: Substrates,
        relation_name: ExternalRequirerRelations = ExternalRequirerRelations.VAULT,
    ) -> None:
        self.name = relation_name.value
        super().__init__(parent=dependent, key=self.name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.workload = self.dependent.vault_config_manager.workload
        self.state = state
        self.substrate = substrate
        self.relation_name = relation_name

    def is_ready(self) -> bool:
        """Checks that we are ready with vault."""
        return self.vault_state() == VaultConfigurationState.ACTIVE

    def assert_should_integrate(self) -> bool:
        """Checks if we should integrate vault."""
        return self.state.enable_encryption_at_rest

    def ensures_config_stored(self):
        """Ensures that the config is stored in the app peer databag for resiliency."""
        if self.state.app_peer_data.enable_encryption_at_rest is None:
            self.state.app_peer_data.enable_encryption_at_rest = (
                self.dependent.config.enable_encryption_at_rest
            )
            logger.debug("Stored enable-encryption-at-rest config value in databag.")

    def ensures_value_is_not_updated(self):
        """Ensures that we don't update the config value after startup."""
        if (
            self.state.app_peer_data.enable_encryption_at_rest is None
        ):  # We haven't run the leader elected event yet.
            logger.info("We haven't elected a leader yet.")
            raise WaitingForLeaderError
        if self.state.enable_encryption_at_rest != self.dependent.config.enable_encryption_at_rest:
            logger.error("Cannot disable / enable encryption at rest after it is set at startup")
            raise InvalidConfigError(
                f"Revert config enable-encryption-at-rest to {self.state.enable_encryption_at_rest}"
            )

    def generate_nonce(self):
        """Sets the nonce in the databag (once per unit)."""
        if self.state.vault_state.nonce:
            return
        self.state.vault_state.nonce = secrets.token_hex(16)

    def get_subnets(self) -> list[str]:
        """Gets the ordered list of subnets for that specific relation."""
        if not self.state.vault_relation:
            return []
        if not (bindings := self.model.get_binding(self.state.vault_relation)):
            return []
        egress_subnets = [str(subnet) for subnet in bindings.network.egress_subnets[0].subnets()]
        egress_subnets.append(str(bindings.network.interfaces[0].subnet))
        return sorted(egress_subnets)

    def get_nonce(self) -> str:
        """Gets the nonce for that unit."""
        if not self.state.vault_state.nonce:
            raise ValueError("No nonce created yet")
        return self.state.vault_state.nonce

    def prepare_vault_agent(self, data: vault_kv.VaultKvProviderSchema) -> None:
        """Prepares the vault agent with the provided configuration."""
        self.state.vault_state.set_from(data)
        self.workload.write(self.workload.paths.vault_cert, data.ca_certificate)
        if not self._check_connectivity(data):
            raise ValueError("Connectivity failed.")
        self.workload.write(self.workload.paths.role_id, data.credentials["role-id"])
        self.workload.write(self.workload.paths.role_secret_id, data.credentials["role-secret-id"])
        self.dependent.vault_config_manager.set_environment()
        self.workload.start()

        # Trigger the startup.
        self.charm.on.start.emit()

    def _check_connectivity(self, data: vault_kv.VaultKvProviderSchema):
        """Checks that the connectivity to vault works."""
        local_path = TRUST_STORE_PATH / TrustStoreFiles.VAULT.value
        self.workload.copy_to_unit(
            self.workload.paths.vault_cert,
            local_path,
        )
        client = hvac.Client(data.vault_url, verify=f"{local_path}")
        try:
            _ = client.auth.approle.login(
                role_id=data.credentials["role-id"], secret_id=data.credentials["role-secret-id"]
            )
            local_path.unlink()
            return True
        except Exception as e:
            logger.warning("Failed to connect to vault: %s", e)
            local_path.unlink()
            return False

    def vault_state(self) -> VaultConfigurationState:
        """Computes the state object for the vault."""
        if self.state.enable_encryption_at_rest != self.dependent.config.enable_encryption_at_rest:
            return VaultConfigurationState.INVALID_CONFIG
        if not self.state.enable_encryption_at_rest and self.state.vault_relation:
            return VaultConfigurationState.VAULT_INTEGRATED
        if not self.state.enable_encryption_at_rest:
            return VaultConfigurationState.DISABLED
        if not self.state.vault_relation:
            return VaultConfigurationState.VAULT_NOT_INTEGRATED
        data = self.state.vault_state.get()
        if not data:
            return VaultConfigurationState.MISSING_DATA
        if not self._check_connectivity(data):
            return VaultConfigurationState.VAULT_UNREACHABLE
        if not self.workload.active():
            return VaultConfigurationState.VAULT_AGENT_FAILED
        return VaultConfigurationState.ACTIVE

    def rotate_master_key(self) -> None:
        """Rotates the vault master key."""
        vault_state = self.vault_state()
        match vault_state:
            case VaultConfigurationState.ACTIVE:
                pass
            case VaultConfigurationState.DISABLED:
                raise ImpossibleToRotateMasterKeyError(
                    "Encryption at rest not enabled on this application."
                )
            case _:
                raise ImpossibleToRotateMasterKeyError(
                    self.map_state_to_status(vault_state).message
                )

        self.dependent.workload.stop()

        try:
            self.dependent.workload.mongod_command_standalone(
                "--config",
                [f"{self.dependent.workload.paths.config_file}", "--vaultRotateMasterKey"],
            )
        except WorkloadExecError as e:
            raise ImpossibleToRotateMasterKeyError("Failed to rotate master key") from e
        finally:
            # Start anyway, we don't want to leave the service not running
            self.dependent.workload.start()

    def map_state_to_status(self, state: VaultConfigurationState) -> StatusObject:
        """Maps a state to its status."""
        match state:
            case VaultConfigurationState.INVALID_CONFIG:
                return VaultStatuses.INVALID_CONFIG.value
            case VaultConfigurationState.VAULT_INTEGRATED:
                return VaultStatuses.VAULT_INTEGRATED.value
            case VaultConfigurationState.VAULT_NOT_INTEGRATED:
                return VaultStatuses.VAULT_NOT_INTEGRATED.value
            case VaultConfigurationState.MISSING_DATA:
                return VaultStatuses.MISSING_DATA.value
            case VaultConfigurationState.VAULT_UNREACHABLE:
                return VaultStatuses.VAULT_UNREACHABLE.value
            case VaultConfigurationState.VAULT_AGENT_FAILED:
                return VaultStatuses.VAULT_AGENT_FAILED.value
            case VaultConfigurationState.ACTIVE | VaultConfigurationState.DISABLED:
                return VaultStatuses.ACTIVE.value

    @override
    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        charm_statuses: dict[Scope, list[StatusObject]] = {"app": [], "unit": []}
        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        state = self.vault_state()
        status = self.map_state_to_status(state)
        match state:
            case VaultConfigurationState.ACTIVE | VaultConfigurationState.DISABLED:
                pass
            case (
                VaultConfigurationState.MISSING_DATA
                | VaultConfigurationState.VAULT_UNREACHABLE
                | VaultConfigurationState.VAULT_AGENT_FAILED
            ):
                charm_statuses["unit"].append(status)
            case _:
                charm_statuses["app"].append(status)
                charm_statuses["unit"].append(status)
        return charm_statuses[scope]

    def set_status(self, status: StatusObject, scope: Literal["both"] | Scope):
        """Sets a status for scope app or unit, or both."""
        if scope == "unit" or scope == "both":
            self.state.statuses.set(status, component=self.name, scope="unit")
        if not self.charm.model.unit.is_leader():
            return
        if scope == "app" or scope == "both":
            self.state.statuses.set(status, component=self.name, scope="app")

    def clear_statuses(self, scope: Literal["both"] | Scope):
        """Sets a status for scope app or unit, or both."""
        logger.info(f"Clearing statuses for {scope=}")
        if scope == "unit" or scope == "both":
            self.state.statuses.clear(component=self.name, scope="unit")
        if not self.charm.model.unit.is_leader():
            return
        if scope == "app" or scope == "both":
            self.state.statuses.clear(component=self.name, scope="app")
