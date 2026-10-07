#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant

from tests.integration.helpers.constants import (
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    MONGOS_APP_NAME,
    MONGOS_CLUSTER_COMPONENTS,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.jubilant_mongos import (
    assert_mongos_tls_enabled,
    build_cluster,
    deploy_cluster_components,
)
from tests.integration.helpers.jubilant_tls import (
    integrate_apps_with_tls,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    deploy_cluster_components(
        juju,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        application_path,
    )
    build_cluster(juju, substrate, integrate_with_mongos=False)

    config = {"ca-common-name": "Test CA"}
    juju.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
        config=config,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, TLS_CERTIFICATES_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )


def test_mongos_tls_enabled(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests race condition: mongos charm can integrate with TLS and then the config-server."""
    integrate_apps_with_tls(juju, *MONGOS_CLUSTER_COMPONENTS)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, *MONGOS_CLUSTER_COMPONENTS, idle_period=20
        ),
        timeout=TIMEOUT,
    )
    integrate_apps_with_tls(juju, MONGOS_APP_NAME)

    # integrate mongos with config-server
    juju.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGOS_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )

    assert_mongos_tls_enabled(juju, substrate)
