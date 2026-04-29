#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

from juju.model import Model
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.architecture import architecture
from tests.integration.helpers.tls import (
    CLIENT_TLS_RELATION_NAME,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)

ETCD_APP_NAME = "charmed-etcd"
ETCD_OFFER = "etcd-integration"
ETCD_RELATION = "etcd-client"


logger = logging.getLogger(__name__)


async def deploy_etcd(ops_test: OpsTest, lxd_model: Model) -> None:
    """Deploy etcd in the LXD model and offer its relation."""
    with ops_test.model_context("secondary"):
        await lxd_model.set_constraints({"arch": architecture})

        await lxd_model.deploy(
            TLS_CERTIFICATES_APP_NAME,
            channel=TLS_CERTIFICATES_CHANNEL,
            base=TLS_CERTIFICATES_BASE,
        )

        await lxd_model.deploy(
            ETCD_APP_NAME,
            channel="3.6/stable",
        )

        await lxd_model.wait_for_idle(
            apps=[ETCD_APP_NAME, TLS_CERTIFICATES_APP_NAME], status="active"
        )

        await lxd_model.integrate(
            f"{TLS_CERTIFICATES_APP_NAME}",
            f"{ETCD_APP_NAME}:{CLIENT_TLS_RELATION_NAME}",
        )
        await lxd_model.wait_for_idle(
            apps=[ETCD_APP_NAME, TLS_CERTIFICATES_APP_NAME], status="active"
        )
        offer_command = f"offer {lxd_model.info.name}.{ETCD_APP_NAME}:{ETCD_RELATION} {ETCD_OFFER}"
        await ops_test.juju(*offer_command.split())


async def consume_etcd_offer(ops_test: OpsTest, lxd_model: Model) -> None:
    """Consume the etcd offer from the main testing model."""
    consume_command = f"consume admin/{lxd_model.info.name}.{ETCD_OFFER}"
    await ops_test.juju(*consume_command.split())


async def integrate_shard_with_etcd(
    ops_test: OpsTest,
    apps: list[str],
) -> None:
    for app in apps:
        await ops_test.model.integrate(f"{app}:etcd", ETCD_OFFER)


async def teardown_etcd_offer(ops_test: OpsTest, lxd_model: Model) -> None:
    """Remove consumed etcd offer and remote offer."""
    await ops_test.model.remove_saas(ETCD_OFFER)

    remove_offer_command = f"remove-offer admin/{lxd_model.info.name}.{ETCD_OFFER} --force --yes"
    await ops_test.juju(*remove_offer_command.split())
