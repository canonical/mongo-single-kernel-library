#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from datetime import datetime, timedelta

import jubilant
from data_platform_helpers.advanced_statuses.models import StatusObject
from dateutil.parser import parse
from ops import StatusBase

logger = logging.getLogger(__name__)


def does_status_match(
    model_status: jubilant.Status,
    expected_unit_statuses: dict[str, list[StatusObject]] | None = None,
    expected_app_statuses: dict[str, list[StatusObject]] | None = None,
    num_units: dict[str, int] | None = None,
) -> bool:
    """Check that current app and/or unit status matches expectation for given apps.

    Args:
        model_status: represents the jubilant model's current status
        expected_unit_statuses: dict mapping app name to list of expected StatusObject for units
        expected_app_statuses: dict mapping app name to its list of expected StatusObject
        num_units: dict mapping app name to expected number of units
    """
    return (
        (
            expected_unit_statuses is None
            or _does_unit_workload_status_match(model_status, expected_unit_statuses)
        )
        and (
            expected_app_statuses is None
            or _does_app_status_match(model_status, expected_app_statuses)
        )
        and (num_units is None or verify_unit_count(model_status, unit_count=num_units))
    )


def _does_unit_workload_status_match(
    model_status: jubilant.Status, expected_statuses: dict[str, list[StatusObject]]
) -> bool:
    """Check that current workload status matches expectation for given apps' units.

    Args:
        model_status: represents the jubilant model's current status
        expected_statuses: dict mapping app names to list of expected StatusObject
    """
    return all(
        all(
            any(
                does_message_match(unit_status.workload_status.message, status)
                for status in expected_status
            )
            for unit_status in model_status.get_units(app).values()
        )
        for app, expected_status in expected_statuses.items()
    )


def _does_app_status_match(
    model_status: jubilant.Status, expected_statuses: dict[str, list[StatusObject]]
) -> bool:
    """Check that current app status matches expectation for given apps.

    Args:
        model_status: represents the jubilant model's current status
        expected_statuses: dict mapping app names to list of expected StatusObject
    """
    return all(
        any(
            does_message_match(model_status.apps.get(app).app_status.message, status)
            for status in expected_status
        )
        for app, expected_status in expected_statuses.items()
    )


def does_message_match(expected_status_message: str, status: StatusObject) -> bool:
    """Check if the status message matches the expected message."""
    try:
        juju_status = StatusBase.from_name(status.status, status.message)
        return (
            expected_status_message == juju_status.message
            or expected_status_message.startswith(juju_status.message)
            or juju_status.message.startswith(f"{expected_status_message:.40}")
            or (
                status.short_message is not None and status.short_message in expected_status_message
            )
        )
    except KeyError as e:
        logger.error("Error attempting to convert StatusObject to ops.StatusBase: %s", e)
        return False


def are_apps_active_and_agents_idle(
    status: jubilant.Status,
    *apps: str,
    idle_period: int = 0,
    unit_count: int | dict[str, int] | None = None,
) -> bool:
    """Check that all given apps are active, their agents idle (optional idle interval too).

    Optionally verify unit count as well.

    Args:
        status: represents the jubilant model's current status
        apps: A list of applications whose statuses to test against
        idle_period: Seconds to wait for the agents of each application unit to be idle.
        unit_count: The desired number of units to wait for, can be > to 0.
            If set as int, this value is expected for all apps but if more granularity is needed,
            pass a dictionary such as: {"app1": 2, "app2": 1, ...}, if set to -1, the check
            only happens at the application level.
    """
    return (
        jubilant.all_active(status, *apps)
        and jubilant.all_agents_idle(status, *apps)
        and _check_apps_idle_period(status, *apps, idle_period=idle_period)
        and verify_unit_count(status, *apps, unit_count=unit_count)
    )


def are_agents_idle(
    status: jubilant.Status,
    *apps: str,
    idle_period: int = 0,
    unit_count: int | dict[str, int] | None = None,
) -> bool:
    """Check that agents of all given apps are idle (optional idle interval too).

    Optionally verify unit count as well.

    Args:
        status: represents the jubilant model's current status
        apps: A list of applications whose statuses to test against
        idle_period: Seconds to wait for the agents of each application unit to be idle.
        unit_count: The desired number of units to wait for, should be > 0.
            If set as int, this value is expected for all apps but if more granularity is needed,
            pass a dictionary such as: {"app1": 2, "app2": 1, ...}, if set to -1, the check
            only happens at the application level.
    """
    return (
        jubilant.all_agents_idle(status, *apps)
        and _check_apps_idle_period(status, *apps, idle_period=idle_period)
        and verify_unit_count(status, *apps, unit_count=unit_count)
    )


def _check_apps_idle_period(status: jubilant.Status, *apps: str, idle_period: int) -> bool:
    return all(
        parse(unit.juju_status.since, ignoretz=True) + timedelta(seconds=idle_period)
        < datetime.now()
        for app in apps
        for unit in status.get_units(app).values()
    )


def verify_unit_count(
    status: jubilant.Status, *apps: str, unit_count: int | dict[str, int] | None = None
):
    """Verify the unit count for an application.

    Args:
        status: represents the jubilant model's current status
        apps: A list of applications whose statuses to test against
        unit_count: The desired number of units to wait for, can be >= to -1
            if set as int, this value is expected for all apps but if more granularity is needed,
            pass a dictionary such as: {"app1": 2, "app2": 1, ...}, if set to -1, the check
            only happens at the application level.
    """
    if not unit_count:
        return True

    if isinstance(unit_count, int):
        if unit_count == 0:
            return True
        unit_count = dict.fromkeys(apps, unit_count)
    elif not unit_count:
        unit_count = dict.fromkeys(apps, -1)
    else:
        for app in apps:
            if app not in unit_count:
                unit_count[app] = 1

    return all(count == len(status.get_units(app)) for app, count in unit_count.items())
