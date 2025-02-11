#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The observability manager.

This class is purely there for separation of purposes, it will just include the
right observability stack.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ops.framework import Object

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.models import OBSERVABILITY_CONFIG
from single_kernel_mongo.config.relations import (
    ExternalProviderRelations,
)
from single_kernel_mongo.lib.charms.grafana_agent.v0.cos_agent import COSAgentProvider
from single_kernel_mongo.lib.charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from single_kernel_mongo.lib.charms.loki_k8s.v0.loki_push_api import LogProxyConsumer
from single_kernel_mongo.lib.charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointProvider,
)
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


class ObservabilityManager(Object):
    """Include the right observability stack."""

    def __init__(
        self,
        dependent: MongoDBOperator,
        state: CharmState,
        substrate: Substrates,
    ) -> None:
        super().__init__(dependent, ExternalProviderRelations.LOGGING.value)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.substrate = substrate

        if self.substrate == Substrates.VM:
            self._grafana_agent = COSAgentProvider(
                self.charm,
                metrics_rules_dir=f"{OBSERVABILITY_CONFIG.metrics_rules_dir}",
                logs_rules_dir=f"{OBSERVABILITY_CONFIG.logs_rules_dir}",
                dashboard_dirs=[f"{OBSERVABILITY_CONFIG.grafana_dashboards}"],
                log_slots=OBSERVABILITY_CONFIG.log_slots,
                scrape_configs=self.mongo_scrape_config,
            )
        else:
            self.metrics_endpoint = MetricsEndpointProvider(
                self.charm,
                refresh_event=[self.charm.on.start, self.charm.on.update_status],
                jobs=self.mongo_scrape_config(),
                alert_rules_path=f"{OBSERVABILITY_CONFIG.k8s_prometheus}",
            )
            self.grafana_dashboards = GrafanaDashboardProvider(
                self.charm, dashboards_path=f"{OBSERVABILITY_CONFIG.grafana_dashboards}"
            )
            self.loki_push = LogProxyConsumer(
                self.charm,
                log_files=[
                    f"{self.dependent.workload.paths.log_file}",
                    f"{self.dependent.workload.paths.audit_file}",
                ],
                relation_name=ExternalProviderRelations.LOGGING.value,
                container_name=self.dependent.role.name,
            )

    def mongo_scrape_config(self) -> list[dict[str, Any]]:
        """Generates scrape config for the mongo metrics endpoint."""
        return [
            {
                "metrics_path": "/metrics",
                "static_configs": [
                    {
                        "targets": [
                            f"{self.state.unit_peer_data.internal_address}:{OBSERVABILITY_CONFIG.mongodb_exporter_port}"
                        ],
                        "labels": {
                            "cluster": self.state.config_server_name or self.charm.app.name,
                        },
                    }
                ],
            }
        ]
