"""cyhy_kevsync Python library and tool."""

# Standard Python Libraries
import argparse
import logging
import sys

# Third-Party Libraries
from pydantic import ValidationError
from rich.logging import RichHandler
from rich.traceback import install as traceback_install

# cisagov Libraries
from cyhy_config import find_config, read_config
from ._version import __version__
from . import sync


def main() -> None:
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
        # datefmt="%Y-%m-%d %H:%M:%S",
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

    # TODO Do KEV syncing
    sync()

    # Stop logging and clean up
    logging.shutdown()
