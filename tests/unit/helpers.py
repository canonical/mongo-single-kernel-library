import factory

from single_kernel_mongo.config.literals import LOCALHOST, MongoPorts
from single_kernel_mongo.utils.mongo_config import MongoConfiguration


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
