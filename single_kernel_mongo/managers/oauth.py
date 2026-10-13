# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The manager for the identity provider CA bundle: the oauth-certificate-transfer relation."""

from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

from charmlibs.interfaces.certificate_transfer import CertificateTransferRequires
from ops.framework import Object

from single_kernel_mongo.config.literals import (
    TRUST_STORE_PATH,
    CharmKind,
    Substrates,
    TrustStoreFiles,
)
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    InvalidOAuthWithShardError,
)
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = getLogger(__name__)


class OAuthManager(Object):
    """Manages the identity provider CA bundle on replica sets, config-servers and routers.

    The mongodb charm holds the `oauth-certificate-transfer` relation (`with_relations=True`):
    every unit keeps the certificates it receives and writes the bundle, and a config-server
    shares it on every `cluster` relation. Routers (`with_relations=False`) keep and write the
    bundle the config-server shared.
    """

    def __init__(
        self,
        dependent: OperatorProtocol,
        state: CharmState,
        substrate: Substrates,
        with_relations: bool = True,
        cert_relation_name: ExternalRequirerRelations = ExternalRequirerRelations.OAUTH_CERT,
    ):
        self.name = "oauth"
        super().__init__(parent=dependent, key=self.name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.workload = self.dependent.workload
        self.state = state
        self.substrate = substrate
        self.cert_relation_name = cert_relation_name
        self.with_relations = with_relations
        self.certificate_transfer: CertificateTransferRequires | None = None
        if with_relations:
            self.certificate_transfer = CertificateTransferRequires(
                self.charm, cert_relation_name.value
            )

    def assert_pass_hook_checks(self) -> None:
        """Runs the hook checks of the certificate handlers."""
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("DB is not initialised")
        if self.state.is_role(MongoDBRoles.SHARD):
            raise InvalidOAuthWithShardError("OAuth is not supported on shards")

    # Certificates (oauth-certificate-transfer relation, or the cluster bundle on routers)

    def store_certificates(self, certificates: set[str]) -> None:
        """Runs when the certificate set changed (every unit)."""
        if self.state.oauth_cert_relation is None:
            # A deferred event re-run after certificates-removed: do not restore a stale chain.
            logger.info("Not storing the OAuth CA certificates: the CA relation is gone.")
            return
        self.assert_pass_hook_checks()
        self.state.oauth.chain = sorted(certificates)
        self.sync_certificate_files()
        if self.charm.unit.is_leader():
            self.share_ca_with_mongos()

    def store_certificates_from_bundle(self, bundle: str | None) -> None:
        """Routers: stores the bundle shared by the config-server as this unit's chain.

        Runs on every router restart: the bundle files are always rewritten or removed.
        """
        self.state.oauth.bundle = bundle
        self.sync_certificate_files()

    def remove_certificates(self) -> None:
        """Runs when the CA relation is broken (every unit): back to publicly trusted CAs."""
        self.state.oauth.chain = None
        self.sync_certificate_files()
        if self.charm.unit.is_leader():
            self.share_ca_with_mongos()

    def reconcile_certificates(self) -> None:
        """Update-status (mongodb): applies the certificate set the relation carries now.

        Catches up on a lost event, and publishes the bundle again to the routers the leader
        could not update at the time.
        """
        if not self.state.db_initialised:
            logger.debug("Not reconciling the OAuth CA certificates: DB is not initialised.")
            return
        relation = self.state.oauth_cert_relation
        if relation is None or self.certificate_transfer is None:
            if not self.state.oauth.chain:
                logger.debug("Not reconciling the OAuth CA certificates: no CA relation.")
                return
            logger.info("The OAuth CA relation is gone, removing the stored certificates.")
            self.remove_certificates()
            return
        if self.state.is_role(MongoDBRoles.SHARD):
            logger.debug("Not reconciling the OAuth CA certificates: shards do not support OAuth.")
            return
        certificates = self.certificate_transfer.get_all_certificates(relation.id)
        if sorted(certificates) != (self.state.oauth.chain or []):
            logger.info("The stored OAuth CA certificates differ from the relation, storing them.")
            self.store_certificates(certificates)
        elif self.charm.unit.is_leader():
            self.share_ca_with_mongos()

    def sync_certificate_files(self) -> None:
        """Writes the stored bundle for the workload and, on mongodb, a copy for the charm.

        Removes both files when no chain is stored. The charm copy is for the charm's own
        HTTPS requests to the identity provider. Routers make none, so they keep no copy in the
        trust-anchor directory, which on a VM subordinate belongs to the client application's
        machine.
        """
        bundle_file = self.workload.paths.oauth_certificates_file
        charm_copy = TRUST_STORE_PATH / TrustStoreFiles.OAUTH.value
        is_mongod = self.dependent.name == CharmKind.MONGOD
        if bundle := self.state.oauth.bundle:
            self.workload.write(bundle_file, bundle)
            if is_mongod:
                with open(charm_copy, mode="w") as fd:
                    fd.write(bundle)
        else:
            if self.workload.exists(bundle_file):
                self.workload.delete(bundle_file)
            if is_mongod and charm_copy.is_file():
                charm_copy.unlink()

    # Sharded clusters

    def share_ca_with_mongos(self) -> None:
        """Config-server: publishes (or removes) the bundle on every cluster relation."""
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            logger.debug("Not sharing the OAuth CA bundle: only a config-server has routers.")
            return
        cluster_manager = self.dependent.cluster_manager  # type: ignore[attr-defined]
        cluster_manager.update_oauth_ca_to_mongos()
