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

from cyhy_kevsync.log_filters import RedactPasswordFilter

from . import kev_sync
from ._version import __version__
from .models.config_model import KEVSyncConfig


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

    # Set up root logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(rich_tracebacks=True, show_path=args.log_level == "debug")
        ],
    )
    # Add a filter to redact passwords from URLs to all handlers of the root logger
    password_redact_filter = RedactPasswordFilter()
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(password_redact_filter)

    # Set logging level for our package
    logger = logging.getLogger(__package__)
    logger.setLevel(args.log_level.upper())
    logger = logging.getLogger("cyhy_config")
    logger.setLevel(args.log_level.upper())

    # Install Rich tracebacks and only show locals when log level is debug as
    # there may be sensitive data we don't normally want to expose
    traceback_install(show_locals=args.log_level == "debug")

    # Find the configuration file
    try:
        config_file = find_config(args.config_file)
    except FileNotFoundError:
        sys.exit(1)

    # Read the configuration file
    try:
        config = read_config(config_file, KEVSyncConfig)
    except ValidationError:
        sys.exit(1)

    # Initialize the database
    await initialize_db(config.kevsync.db_auth_uri, config.kevsync.db_name)
    kev_data = await kev_sync.fetch_kev_data(config.kevsync.json_url)
    if config.kevsync.schema_url:
        await kev_sync.validate_kev_data(kev_data, config.kevsync.schema_url)
    else:
        logger.warning("No schema URL provided, skipping KEV JSON validation.")
    created_kev_docs = await kev_sync.add_kev_docs(kev_data)
    removed_kev_docs = await kev_sync.remove_outdated_kev_docs(created_kev_docs)

    # Stop logging and clean up
    logging.shutdown()


def main():
    asyncio.run(main_async())
