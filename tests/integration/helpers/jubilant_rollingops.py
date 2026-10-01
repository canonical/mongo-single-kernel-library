#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import logging

import jubilant

from tests.integration.helpers.constants import (
    CLIENT_TLS_RELATION_NAME,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle

ETCD_APP_NAME = "charmed-etcd"
logger = logging.getLogger(__name__)


def deploy_etcd(juju: jubilant.Juju) -> None:
    """Deploy etcd and enable client TLS."""
    juju.deploy(
        charm=TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
    )

    juju.deploy(
        charm=ETCD_APP_NAME,
        channel="3.6/stable",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            ETCD_APP_NAME,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    juju.integrate(
        f"{TLS_CERTIFICATES_APP_NAME}",
        f"{ETCD_APP_NAME}:{CLIENT_TLS_RELATION_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            ETCD_APP_NAME,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


def integrate_shard_with_etcd(
    juju: jubilant.Juju,
    *apps: str,
) -> None:
    """Relate etcd to all listed apps."""
    for app in apps:
        juju.integrate(f"{app}:etcd", f"{ETCD_APP_NAME}:etcd-client")
