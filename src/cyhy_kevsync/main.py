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
from pydantic import ValidationError
from rich.logging import RichHandler
from rich.traceback import install as traceback_install

# cisagov Libraries
from cyhy_kevsync.log_filters import RedactPasswordFilter

from . import kev_sync
from ._version import __version__
from .models.config_model import KEVSyncConfig


async def setup_logging(log_level: Optional[str] = None) -> logging.Logger:
    """Set up all logging."""
    # MongoDB is too verbose if set to DEBUG, so we only want to show INFO and
    # above at the root logger.  We'll set the log level for our package and the
    # cyhy_config package separately.
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        # TODO what does show_path do, and is this the same as traceback_install below?
        handlers=[RichHandler(rich_tracebacks=True, show_path=log_level == "debug")],
    )
    # Add a filter to redact passwords from URLs to all handlers of the root logger
    password_redact_filter = RedactPasswordFilter()
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(password_redact_filter)

    # Install Rich tracebacks and only show locals when log level is debug as
    # there may be sensitive data we don't normally want to expose
    traceback_install(show_locals=log_level == "debug")

    package_logger = logging.getLogger(__package__)
    if log_level:
        package_logger.setLevel(log_level.upper())
        config_logger = logging.getLogger("cyhy_config")
        config_logger.setLevel(log_level.upper())
    return package_logger


async def do_kev_sync(
    config_file: Optional[str] = None, arg_log_level: Optional[str] = None
) -> None:
    """Perform the KEV synchronization."""
    logger = await setup_logging(arg_log_level)

    # Get the configuration
    try:
        config = get_config(file_path=config_file, model=KEVSyncConfig)
    except ValidationError:
        sys.exit(1)
    except FileNotFoundError:
        sys.exit(1)

    if not arg_log_level and config.kevsync.log_level:
        # Update log levels from config if they were not set by an argument
        logger = await setup_logging(config.kevsync.log_level)

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
