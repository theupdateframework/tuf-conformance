#!/usr/bin/env python
"""TUF Client using python-tuf"""

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

import argparse
import shutil
import os
import sys

# constants


def init(metadata_url: str, metadata_dir: str, trusted_root: str) -> None:
    """Initialize local trusted metadata
    
    No need to actually run python-tuf code at this point"""
    shutil.copyfile(trusted_root, os.path.join(metadata_dir, "root.json"))
    print(f"python-tuf test client: Initialized repository in {metadata_dir}")


def main() -> None:
    """Main TUF Client Example function"""

    client_args = argparse.ArgumentParser(description="TUF Client Example")

    sub_command = client_args.add_subparsers(dest="sub_command")
    init_parser = sub_command.add_parser(
        "init",
        help="Initialize client with given trusted root",
    )

    init_parser.add_argument("--metadata-url", required=True)
    init_parser.add_argument("--metadata-dir", required=True)
    init_parser.add_argument("--trusted-root", required=True)


    command_args = client_args.parse_args()

    # initialize the TUF Client Example infrastructure
    if command_args.sub_command == "init":
        init(command_args.metadata_url, command_args.metadata_dir, command_args.trusted_root)
    else:
        client_args.print_help()


if __name__ == "__main__":
    sys.exit(main())
