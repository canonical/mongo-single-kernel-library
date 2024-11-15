#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Some helpers functions that doesn't belong anywhere else."""

import base64
import re


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
