from pathlib import Path

from parameterized import parameterized

from single_kernel_mongo.config.roles import (
    K8S_MONGOD,
    K8S_MONGOS,
    VM_MONGOD,
    VM_MONGOS,
    Role,
)
from single_kernel_mongo.core.workload import MongoPaths


@parameterized.expand([[K8S_MONGOD], [K8S_MONGOS], [VM_MONGOS], [VM_MONGOD]])
def test_mongo_paths(role: Role):
    paths = MongoPaths(role)

    assert paths.config_file.parent == Path(role.paths["CONF"])
    assert paths.keyfile.parent == Path(role.paths["CONF"])
    assert paths.log_file.parent == Path(role.paths["LOGS"])
    assert paths.audit_file.parent == Path(role.paths["LOGS"])
    assert paths.ext_pem_file.parent == Path(role.paths["CONF"])
    assert paths.ext_ca_file.parent == Path(role.paths["CONF"])
    assert paths.int_pem_file.parent == Path(role.paths["CONF"])
    assert paths.int_ca_file.parent == Path(role.paths["CONF"])

    assert all(path.parent == Path(role.paths["CONF"]) for path in paths.tls_files)
