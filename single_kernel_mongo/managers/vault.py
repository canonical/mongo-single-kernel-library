# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The managers for the vault relations between vault and mongodb charms."""

from __future__ import annotations

import secrets
import socket
from datetime import timedelta
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
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    PrivateKey,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from single_kernel_mongo.lib.charms.vault_k8s.v0 import vault_kv
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator

logger = getLogger(__name__)

VAULT_CA_SUBJECT = "Vault Agent self signed CA"


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
        self.config_manager = self.dependent.vault_config_manager

        self.common_name = (
            f"{self.state.unit_peer_data.name.replace('/', '')}-{self.state.model.uuid}"
        )
        unit_id = self.charm.unit.name.split("/")[1]

        self.sans_dns = frozenset(
            [
                f"{self.charm.app.name}-{unit_id}",
                socket.getfqdn(),
                "localhost",
                f"{self.charm.app.name}-{unit_id}.{self.charm.app.name}-endpoints",
            ]
        )
        self.sans_ip = frozenset([self.state.bind_address, "127.0.0.1"])

    def is_ready(self) -> bool:
        """Checks that we are ready with vault."""
        return self.vault_state() == VaultConfigurationState.ACTIVE

    def assert_should_integrate(self) -> bool:
        """Checks if we should integrate vault."""
        return self.state.enable_encryption_at_rest

    def ensures_config_stored(self) -> None:
        """Ensures that the config is stored in the app peer databag for resiliency."""
        if self.state.app_peer_data.enable_encryption_at_rest is None:
            self.state.app_peer_data.enable_encryption_at_rest = (
                self.dependent.config.enable_encryption_at_rest
            )
            logger.debug("Stored enable-encryption-at-rest config value in databag.")

    def _generate_vault_ca_certificate(self) -> tuple[str, str]:
        """Generate Vault CA certificates valid for 50 years.

        Returns:
            Tuple[str, str]: CA Private key, CA certificate
        """
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name=VAULT_CA_SUBJECT,
            validity=timedelta(days=365 * 50),
        )
        return str(ca_private_key), str(ca_certificate)

    def generate_vault_ca_certificate(self) -> None:
        """Generate and store the Vault CA private keys."""
        if self.state.enable_encryption_at_rest:
            ca_private_key, ca_certificate = self._generate_vault_ca_certificate()
            self.state.vault_state.agent_ca_private_key = ca_private_key
            self.state.vault_state.agent_ca_certificate = ca_certificate

    def generate_vault_unit_certificate(
        self,
        common_name: str,
        sans_ip: frozenset[str],
        sans_dns: frozenset[str],
        ca_certificate: str,
        ca_private_key: str,
    ) -> tuple[str, str]:
        """Generate Vault unit certificates valid for 50 years.

        Args:
            common_name: Common name of the certificate
            sans_ip: Subject alternative IP addresses of the certificate
            sans_dns: Subject alternative names of the certificate
            ca_certificate: CA certificate
            ca_private_key: CA private key

        Returns:
            Tuple[str, str]: Private key, Certificate
        """
        vault_private_key = generate_private_key()
        csr = generate_csr(
            private_key=vault_private_key,
            common_name=common_name,
            sans_ip=sans_ip,
            sans_dns=sans_dns,
        )
        vault_certificate = generate_certificate(
            ca=Certificate.from_string(ca_certificate),
            ca_private_key=PrivateKey.from_string(ca_private_key),
            csr=csr,
            validity=timedelta(days=365 * 50),
        )
        return str(vault_private_key), str(vault_certificate)

    def configure_self_signed_certificates(self, restart: bool = False):
        """Configures and restart Vault Agent with new certificates if needed."""
        if not self.assert_should_integrate():
            return

        secret_ca = self.state.vault_state.agent_ca_certificate
        secret_private_key = self.state.vault_state.agent_ca_private_key
        if not secret_ca or not secret_private_key:
            raise WaitingForLeaderError("Still waiting for CA certificate")

        try:
            workload_ca = Certificate.from_string(
                "\n".join(self.workload.read(self.workload.paths.vault_agent_ca))
            )
        except Exception:
            workload_ca = None
        if workload_ca and workload_ca.common_name == VAULT_CA_SUBJECT and workload_ca == secret_ca:
            workload_unit_cert = "\n".join(self.workload.read(self.workload.paths.vault_agent_cert))
            if workload_unit_cert and self._match_sans_request(workload_unit_cert):
                return

        unit_private_key, unit_certificate = self.generate_vault_unit_certificate(
            common_name=self.common_name,
            sans_dns=self.sans_dns,
            sans_ip=self.sans_ip,
            ca_certificate=secret_ca,
            ca_private_key=secret_private_key,
        )

        self.workload.write(self.workload.paths.vault_agent_ca, secret_ca)
        self.workload.write(self.workload.paths.vault_agent_cert, unit_certificate)
        self.workload.write(self.workload.paths.vault_agent_key, unit_private_key)

        if restart and self.is_ready():
            self.config_manager.configure_and_restart(force=True)

    def _match_sans_request(self, unit_cert_content: str) -> bool:
        """Checks if the argument certificate matches the expected values."""
        try:
            unit_cert = Certificate.from_string(unit_cert_content)

            cert_sans_dns = set(unit_cert.sans_dns) if unit_cert.sans_dns else set[str]()
            cert_sans_ip = set(unit_cert.sans_ip) if unit_cert.sans_ip else set[str]()
            current_sans_dns = set(self.sans_dns) if self.sans_dns else set[str]()
            current_sans_ip = set(self.sans_ip) if self.sans_ip else set[str]()

            return (
                cert_sans_dns == current_sans_dns
                and cert_sans_ip == current_sans_ip
                and unit_cert.common_name == self.common_name
            )
        except Exception as e:
            logger.warning("Failed to parse unit certificate attributes: %s", e)
            return False

    def ensures_value_is_not_updated(self) -> None:
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

    def generate_nonce(self) -> None:
        """Sets the nonce in the databag (once per unit)."""
        if self.state.vault_state.nonce:
            return
        self.state.vault_state.nonce = secrets.token_hex(16)

    def get_egress_subnets(self) -> list[str]:
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
        self.configure_self_signed_certificates()
        self.config_manager.set_environment()
        self.workload.start()

        # Trigger the startup.
        self.charm.on.start.emit()

    def _check_connectivity(self, data: vault_kv.VaultKvProviderSchema) -> bool:
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
        if not (data := self.state.vault_state.get()):
            return VaultConfigurationState.MISSING_DATA
        if not self._check_connectivity(data):
            return VaultConfigurationState.VAULT_UNREACHABLE
        if not self.workload.active():
            return VaultConfigurationState.VAULT_AGENT_FAILED
        return VaultConfigurationState.ACTIVE

    def rotate_master_key(self) -> None:
        """Rotates the vault master key."""
        if self.dependent.refresh_in_progress:
            raise ImpossibleToRotateMasterKeyError("Refresh in progress.")
        for manager in (self.dependent.s3_backup_manager, self.dependent.gcs_backup_manager):
            if manager.backup_in_progress():
                raise ImpossibleToRotateMasterKeyError("Backup in progress")
            if manager.restore_in_progress():
                raise ImpossibleToRotateMasterKeyError("Restore in progress")

        match self.vault_state():
            case VaultConfigurationState.ACTIVE:
                pass
            case VaultConfigurationState.DISABLED:
                raise ImpossibleToRotateMasterKeyError(
                    "Encryption at rest not enabled on this application."
                )
            case vault_state:
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

    def set_status(self, status: StatusObject, scope: Literal["both"] | Scope) -> None:
        """Sets a status for scope app or unit, or both."""
        if scope == "unit" or scope == "both":
            self.state.statuses.set(status, component=self.name, scope="unit")
        if not self.charm.model.unit.is_leader():
            return
        if scope == "app" or scope == "both":
            self.state.statuses.set(status, component=self.name, scope="app")

    def clear_statuses(self, scope: Literal["both"] | Scope) -> None:
        """Sets a status for scope app or unit, or both."""
        logger.info(f"Clearing statuses for {scope=}")
        if scope == "unit" or scope == "both":
            self.state.statuses.clear(component=self.name, scope="unit")
        if not self.charm.model.unit.is_leader():
            return
        if scope == "app" or scope == "both":
            self.state.statuses.clear(component=self.name, scope="app")
