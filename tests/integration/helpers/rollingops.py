#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

from pytest_operator.plugin import OpsTest

from tests.integration.helpers.tls import (
    CLIENT_TLS_RELATION_NAME,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)

ETCD_APP_NAME = "charmed-etcd"


logger = logging.getLogger(__name__)


async def deploy_etcd(ops_test: OpsTest) -> None:
    """Deploy etcd and enable client TLS."""
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
    )

    await ops_test.model.deploy(
        ETCD_APP_NAME,
        channel="3.6/stable",
    )

    await ops_test.model.wait_for_idle(
        apps=[ETCD_APP_NAME, TLS_CERTIFICATES_APP_NAME], status="active"
    )

    await ops_test.model.integrate(
        f"{TLS_CERTIFICATES_APP_NAME}",
        f"{ETCD_APP_NAME}:{CLIENT_TLS_RELATION_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[ETCD_APP_NAME, TLS_CERTIFICATES_APP_NAME], status="active"
    )


async def integrate_shard_with_etcd(
    ops_test: OpsTest,
    apps: list[str],
) -> None:
    for app in apps:
        await ops_test.model.integrate(f"{app}:etcd", f"{ETCD_APP_NAME}:etcd-client")
