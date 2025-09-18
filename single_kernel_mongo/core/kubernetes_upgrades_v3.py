"""Kubernetes code for upgrades."""

import dataclasses

import charm_refresh

from single_kernel_mongo.core.abstract_upgrades_v3 import MongoDBRefresh


@dataclasses.dataclass(eq=False)
class KubernetesMongoDBRefresh(
    MongoDBRefresh,
    charm_refresh.CharmSpecificKubernetes,
):
    """Kubernetes specific refresh code."""

    pass
