from pathlib import Path

import factory

from single_kernel_mongo.config.literals import LOCALHOST, InternalUsernames, MongoPorts
from single_kernel_mongo.utils.mongo_config import MongoConfiguration

MODEL_NAME = "deadbeef"
CLUSTER_NAME = "hacked"
# The LDAP group DN the entity tests request as a GROUP role name.
GROUP_DN = "ou=superheroes,ou=users,dc=glauth,dc=com"
# The class the unit tests patch to stub MongoDB calls.
CONNECTION = "single_kernel_mongo.utils.mongo_connection.MongoConnection"


class MongoConfigurationFactory(factory.Factory):
    class Meta:  # noqa
        model = MongoConfiguration

    hosts = {LOCALHOST}
    database = "abadcafe"
    username = InternalUsernames.CHARMED_OPERATOR
    password = "deadbeef"
    roles: set[str] = set()
    tls_enabled = False
    tls_external_ca = Path("")
    port = MongoPorts.MONGODB_PORT
    replset = "cafebabe"
    standalone = False
