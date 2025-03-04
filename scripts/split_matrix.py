#!/usr/bin/env python3
"""Takes the PR comment and parses it into a list of jobs."""

import json
import os
import re

PARSE_REGEX = re.compile(r"\/test(\/?[\d\w*]+)?(\/[\d\w]+)?")

ALL_CHARMS = ["mongodb-operator", "mongodb-k8s-operator", "mongos-operator", "mongos-k8s-operator"]


def parse_comment(comment: str) -> list[str]:  # noqa: C901
    """Comment looks like `/test` or `/test/<Charm Type>/<Charm Substrate`."""
    match = PARSE_REGEX.fullmatch(comment)

    if not match:
        return []

    charm_type: str | None = match.group(1)
    substrate: str | None = match.group(2)

    if charm_type:
        charm_type = charm_type.strip("/").lower()
    if charm_type not in [None, "*", "mongodb", "mongos"]:
        return []

    if substrate:
        substrate = substrate.strip("/").lower()
    if substrate not in [None, "k8s", "vm"]:
        return []

    match (charm_type, substrate):
        case None, None:
            return ALL_CHARMS
        case "*", "k8s":
            return [charm for charm in ALL_CHARMS if "k8s" in charm]
        case "*", "vm":
            return [charm for charm in ALL_CHARMS if "k8s" not in charm]
        case "mongos", None:
            return [charm for charm in ALL_CHARMS if "mongos" in charm]
        case "mongodb", None:
            return [charm for charm in ALL_CHARMS if "mongodb" in charm]
        case _, "k8s":
            return [f"{charm_type}-k8s-operator"]
        case _, "vm":
            return [f"{charm_type}-operator"]
        case _, _:
            return []

    return []


if __name__ == "__main__":
    comment = os.environ["COMMENT"].strip()
    print(json.dumps(parse_comment(comment)))
