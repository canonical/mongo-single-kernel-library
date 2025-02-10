#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Some helpers functions that doesn't belong anywhere else."""

import base64
import re
from functools import partial
from logging import getLogger

from single_kernel_mongo.config.literals import CharmKind, Substrates
from single_kernel_mongo.exceptions import InvalidCharmKindError
from single_kernel_mongo.state.upgrade_state import UnitUpgradePeerData

logger = getLogger(__name__)


def parse_tls_file(raw_content: str) -> bytes:
    """Parse TLS files from both plain text or base64 format."""
    if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
        return (
            re.sub(
                r"(-+(BEGIN|END) [A-Z ]+-+)",
                "\\1",
                raw_content,
            )
            .rstrip()
            .encode("utf-8")
        )
    return base64.b64decode(raw_content)


def generate_relation_departed_key(rel_id: int) -> str:  # noqa
    return f"relation_{rel_id}_departed"


def get_logrotate_pid_command(substrate: Substrates, log_dir: str) -> str:
    """Gets the command that fetches the PID for logrotate template."""
    if substrate == Substrates.K8S:
        return f'pgrep -f "mongod.*--logpath={log_dir}/mongodb.log"'
    return "systemctl show -p MainPID --value snap.charmed-mongodb.mongod.service"


def hostname_from_hostport(host: str) -> str:
    """Takes hostname:port and returns hostname."""
    return host.split(":")[0]


def hostname_from_shardname(host: str) -> str:
    """Takes hostname/ip:port and returns hostname."""
    return host.split("/")[0]


def unit_number(unit: UnitUpgradePeerData) -> int:
    """Gets the unit number from a unit upgrade peer data."""
    return int(unit.component.name.split("/")[-1])


def charm_kind_only(func, charm_kind: CharmKind):
    """Helpful decorator to ensure the charm kind."""

    def wrapper(self, *args, **kwargs):
        if self.dependent.name != charm_kind:
            logger.error(f"Unexpected {func} called on a non {charm_kind.value} charm.")
            raise InvalidCharmKindError(
                f"Unexpected {func} called on a non {charm_kind.value} charm."
            )
        return func(self, *args, **kwargs)

    return wrapper


mongodb_only = partial(charm_kind_only, charm_kind=CharmKind.MONGOD)
mongos_only = partial(charm_kind_only, charm_kind=CharmKind.MONGOS)
