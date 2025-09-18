#!/usr/bin/env python
"""Creates a tag if it does not exist yet."""

import argparse
import logging
import subprocess
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stdout)


def main():
    """Creates a tag if it does not exist yet."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)

    args = parser.parse_args()
    tag = args.tag

    logging.info("Checking if new release tag already exists")
    try:
        tag_commit_sha = subprocess.run(
            ["git", "rev-list", "-n", "1", tag], capture_output=True, check=True, text=True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        logging.info("Release tag does not already exist. Creating tag")
        subprocess.run(["git", "tag", tag, "--annotate", "-m", tag], check=True)
        subprocess.run(["git", "push", "origin", tag], check=True)
    else:
        logging.info("Release tag already exists. Verifying tag")
        head_commit_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, check=True, text=True
        ).stdout.strip()
        if head_commit_sha == tag_commit_sha:
            logging.info("Verified existing tag points to the correct commit")
        else:
            raise ValueError(
                f"Attempted to create tag {tag} on commit {head_commit_sha} but tag already "
                f"exists on commit {tag_commit_sha}"
            )


if __name__ == "__main__":
    main()
