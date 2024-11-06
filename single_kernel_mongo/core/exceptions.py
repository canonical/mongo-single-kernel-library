# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""All exceptions definitions."""


class AmbiguousConfigError(Exception):
    """Raised when the config could correspond to a mongod config or mongos config."""
