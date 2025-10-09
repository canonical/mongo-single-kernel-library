# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The upgrade peer unit relation databag."""

import json
import time
from enum import Enum
from logging import getLogger

from ops.model import Application, Relation, Unit

from single_kernel_mongo.config.literals import Substrates, UnitState
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerData,
    DataPeerUnitData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState

logger = getLogger(__name__)


class UnitUpgradeRelationKeys(str, Enum):
    """The unit upgrade peer relation model."""

    STATE = "state"
    SNAP_REVISION = "snap_revision"
    CURRENT_REVISION = "current_revision"


class AppUpgradeRelationKeys(str, Enum):
    """The app upgrade peer relation model."""

    VERSIONS = "versions"
    UPGRADE_RESUMED = "upgrade-resumed"
    UNUSED_TIMESTAMP = "-unused-timestamp-upgrade-resume-last-updated"


class UnitUpgradePeerData(AbstractRelationState[DataPeerUnitData]):
    """State collection for unit data."""

    component: Unit

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerUnitData,
        component: Unit,
        substrate: Substrates,
    ):
        super().__init__(relation, data_interface, component, None)
        self.data_interface = data_interface
        self.substrate = substrate
        self.unit = component

    @property
    def unit_state(self) -> UnitState | None:
        """Unit upgrade state."""
        if state := self.relation_data.get(UnitUpgradeRelationKeys.STATE.value):
            return UnitState(state)
        return None

    @unit_state.setter
    def unit_state(self, value: UnitState) -> None:
        self.update({UnitUpgradeRelationKeys.STATE.value: value.value})

    @property
    def snap_revision(self) -> str | None:
        """Installed snap revision for this unit."""
        return self.relation_data.get(UnitUpgradeRelationKeys.SNAP_REVISION.value)

    @snap_revision.setter
    def snap_revision(self, value: str):
        self.update({UnitUpgradeRelationKeys.SNAP_REVISION.value: value})

    @property
    def current_revision(self) -> str:
        """The revision of the charm that's running before the upgrade."""
        return self.relation_data.get(UnitUpgradeRelationKeys.CURRENT_REVISION, "-1")

    @current_revision.setter
    def current_revision(self, value: str):
        self.update({UnitUpgradeRelationKeys.CURRENT_REVISION.value: value})


class AppUpgradePeerData(AbstractRelationState[DataPeerData]):
    """State collection for unit data."""

    component: Application

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerData,
        component: Application,
        substrate: Substrates,
    ):
        super().__init__(relation, data_interface, component, None)
        self.data_interface = data_interface
        self.substrate = substrate
        self.unit = component

    @property
    def versions(self) -> dict[str, str] | None:
        """Unit upgrade state."""
        if state := self.relation_data.get(AppUpgradeRelationKeys.VERSIONS.value):
            return json.loads(state)
        return None

    @versions.setter
    def versions(self, value: dict[str, str]) -> None:
        self.update({AppUpgradeRelationKeys.VERSIONS.value: json.dumps(value)})

    @property
    def upgrade_resumed(self) -> bool:
        """Whether user has resumed upgrade with Juju action.

        Reset to `False` after each `juju refresh`
        VM-Only.
        """
        return json.loads(
            self.relation_data.get(AppUpgradeRelationKeys.UPGRADE_RESUMED.value, "false")
        )

    @upgrade_resumed.setter
    def upgrade_resumed(self, value: bool):
        # Trigger peer relation_changed event even if value does not change
        # (Needed when leader sets value to False during `ops.UpgradeCharmEvent`)
        self.update(
            {
                AppUpgradeRelationKeys.UPGRADE_RESUMED.value: json.dumps(value),
                AppUpgradeRelationKeys.UNUSED_TIMESTAMP.value: str(time.time()),
            }
        )
        logger.debug(f"Set upgrade-resumed to {value=}")
