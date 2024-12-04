#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Events helper to fail/succeed events."""

from logging import Logger

from ops.charm import ActionEvent
from ops.framework import EventBase


def fail_action_with_error_log(
    logger: Logger, event: ActionEvent, action: str, message: str
) -> None:
    """Fails an action with the provided error log."""
    logger.error("%s failed: %s", action.capitalize(), message)
    event.fail(message)


def defer_event_with_info_log(logger: Logger, event: EventBase, action: str, message: str) -> None:
    """Defer an action with the provided error log."""
    logger.info("Deferring %s: %s", action, message)
    event.defer()


def success_action_with_info_log(
    logger: Logger, event: ActionEvent, action: str, results: dict[str, str]
) -> None:
    """Succeed an action with log."""
    logger.info("%s completed successfully", action.capitalize())
    event.set_results(results)
