#!/usr/bin/env python
"""Parse a pip version tag into a refresh v3 compatible tag."""

import argparse
import logging
import os
import sys

from packaging.version import Version

logging.basicConfig(level=logging.INFO, stream=sys.stdout)


def main():
    """Parse tag to refresh tag."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--track", required=True, type=int)
    parser.add_argument("--tag", required=True)

    args = parser.parse_args()
    track = args.track
    tag = args.tag

    version = Version(tag)

    if track != version.minor:
        raise ValueError(f"Invalid major MongoDB version: {track=} {version.minor=}")

    refresh_tag = f"v{track}/{version.major}.{version.micro}.0"
    with open(os.environ["GITHUB_OUTPUT"], "a") as file:
        file.write(f"{refresh_tag=}\n")
        logging.info(f"New refresh tag is {refresh_tag}")


if __name__ == "__main__":
    main()
