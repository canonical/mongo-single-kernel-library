#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Definition of MongoDB error codes."""

from enum import IntEnum


class MongoErrorCodes(IntEnum):
    """MongoDB error codes we handle."""

    UNAUTHORIZED = 13
    AUTHENTICATION_FAILED = 18
    ILLEGAL_OPERATION = 20
    ALREADY_INITIALIZED = 23
    OPERATION_FAILED = 96
    FAILED_TO_SATISFY_READ_PREFERENCE = 133
    ROLE_ALREADY_EXISTS = 51002
    USER_ALREADY_EXISTS = 51003
