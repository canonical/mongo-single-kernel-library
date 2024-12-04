from collections.abc import Callable
from unittest.mock import patch

import factory

from single_kernel_mongo.config.literals import LOCALHOST, MongoPorts
from single_kernel_mongo.utils.mongo_config import MongoConfiguration


def patch_network_get(private_address="10.1.157.116") -> Callable:
    def network_get(*args, **kwargs) -> dict:
        """Patch for the not-yet-implemented testing backend needed for `bind_address`.

        This patch decorator can be used for cases such as:
        self.model.get_binding(event.relation).network.bind_address
        """
        return {
            "bind-addresses": [
                {
                    "mac-address": "",
                    "interface-name": "",
                    "addresses": [{"hostname": "", "value": private_address, "cidr": ""}],
                }
            ],
            "bind-address": private_address,
            "egress-subnets": ["10.152.183.65/32"],
            "ingress-addresses": ["10.152.183.65"],
        }

    return patch("ops.testing._TestingModelBackend.network_get", network_get)


class MongoConfigurationFactory(factory.Factory):
    class Meta:  # noqa
        model = MongoConfiguration

    hosts = {LOCALHOST}
    database = "abadcafe"
    username = "operator"
    password = "deadbeef"
    roles: set[str] = set()
    tls_external = False
    tls_internal = False
    port = MongoPorts.MONGODB_PORT
    replset = "cafebabe"
    standalone = False
