"""cyhy_kevsync Python library and tool."""

# Standard Python Libraries
import argparse
import asyncio
import logging
import sys
from typing import Optional

# Third-Party Libraries
from cyhy_config import get_config
from cyhy_db import initialize_db
from cyhy_logging import CYHY_ROOT_LOGGER, setup_logging
from pydantic import ValidationError

from . import kev_sync
from ._version import __version__
from .models.config_model import KEVSyncConfig


async def do_kev_sync(
    config_file: Optional[str] = None, arg_log_level: Optional[str] = None
) -> None:
    """Perform the KEV synchronization."""
    logger = logging.getLogger(f"{CYHY_ROOT_LOGGER}.{__name__}")
    setup_logging(arg_log_level)

    # Get the configuration
    try:
        config = get_config(file_path=config_file, model=KEVSyncConfig)
    except ValidationError:
        sys.exit(1)
    except FileNotFoundError:
        sys.exit(1)

    if not arg_log_level and config.kevsync.log_level:
        # Update log levels from config if they were not set by an argument
        setup_logging(config.kevsync.log_level)

    # Initialize the database
    await initialize_db(config.kevsync.db_auth_uri, config.kevsync.db_name)
    kev_json_feed = await kev_sync.fetch_kev_data(config.kevsync.json_url)
    if config.kevsync.schema_url:
        await kev_sync.validate_kev_data(kev_json_feed, config.kevsync.schema_url)
    else:
        logger.warning("No schema URL provided, skipping KEV JSON validation.")
    created_kev_docs, updated_kev_docs, deleted_kev_docs = await kev_sync.sync_kev_docs(
        kev_json_feed
    )

    # Log the results
    logger.info("KEV synchronization complete.")
    logger.info("Created KEV documents: %d", len(created_kev_docs))
    logger.info("Updated KEV documents: %d", len(updated_kev_docs))
    logger.info("Deleted KEV documents: %d", len(deleted_kev_docs))


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

    await do_kev_sync(args.config_file, args.log_level)

    # Stop logging and clean up
    logging.shutdown()


def main():
    """Run the main function."""
    asyncio.run(main_async())
