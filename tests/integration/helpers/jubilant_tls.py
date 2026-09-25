#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant

from tests.integration.helpers.constants import (
    CLIENT_TLS_RELATION_NAME,
    PEER_TLS_RELATION_NAME,
    TLS_CERTIFICATES_APP_NAME,
)

logger = getLogger(__name__)


def integrate_apps_with_tls(
    juju: jubilant.Juju,
    *apps: str,
    cert_provider_app: str = TLS_CERTIFICATES_APP_NAME,
    peer: bool = True,
    client: bool = True,
) -> None:
    """Integrates a list of applications with self-signed certs operator."""
    for app in apps:
        if peer:
            juju.integrate(
                f"{cert_provider_app}",
                f"{app}:{PEER_TLS_RELATION_NAME}",
            )
        if client:
            juju.integrate(
                f"{cert_provider_app}",
                f"{app}:{CLIENT_TLS_RELATION_NAME}",
            )
