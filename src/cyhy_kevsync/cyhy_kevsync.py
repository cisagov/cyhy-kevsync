"""cyhy_kevsync Python library and tool."""

# Standard Python Libraries
import argparse
import asyncio
import logging
import sys

# Third-Party Libraries
from cyhy_config import find_config, read_config
from cyhy_db import initialize_db
from pydantic import ValidationError
from rich.logging import RichHandler
from rich.traceback import install as traceback_install


from . import DEFAULT_KEV_URL, DEFAULT_KEV_SCHEMA_URL, sync
from ._version import __version__


async def main_async() -> None:
    """Set up logging and call the process function."""
    parser = argparse.ArgumentParser(
        description="Cyber Hygiene known exploited vulnerability (KEV) synchronization tool",
    )
    parser.add_argument(
        "--config-file",
        help="path to the configuration file",
        metavar="config-file",
        type=str,
    )
    parser.add_argument(
        "--log-level",
        "-l",
        help="set the logging level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        format="%(message)s",
        level=args.log_level.upper(),
        handlers=[
            RichHandler(rich_tracebacks=True, show_path=args.log_level == "debug")
        ],
    )

    # Set up tracebacks
    traceback_install(show_locals=True)

    # Find the configuration file
    try:
        config_file = find_config(args.config_file)
    except FileNotFoundError:
        sys.exit(1)

    # Read the configuration file
    try:
        config = read_config(config_file)
    except ValidationError:
        sys.exit(1)

    # Initialize the database
    await initialize_db(
        config.databases["bastion"].auth_uri, config.databases["bastion"].name
    )
    kev_data = await sync.fetch_kev_data(DEFAULT_KEV_URL, DEFAULT_KEV_SCHEMA_URL)
    created_kev_docs = await sync.add_kev_docs(kev_data)
    removed_kev_docs = await sync.remove_outdated_kev_docs(created_kev_docs)

    # Stop logging and clean up
    logging.shutdown()


def main():
    asyncio.run(main_async())
