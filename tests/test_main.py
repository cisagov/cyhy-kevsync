"""Test the main module."""

# Standard Python Libraries
import argparse
import logging
import sys
from unittest.mock import AsyncMock, mock_open, patch

# Third-Party Libraries
from cyhy_logging import CYHY_ROOT_LOGGER
import pytest

# cisagov Libraries
from cyhy_kevsync.main import do_kev_sync, main_async
from cyhy_kevsync.models.config_model import (
    DEFAULT_KEV_SCHEMA_URL,
    DEFAULT_KEV_URL,
    KEVSync,
    KEVSyncConfig,
)


async def test_main_async_no_args():
    """Test the main_async function with no arguments."""
    test_args = ["program"]
    with patch.object(sys, "argv", test_args), patch(
        "cyhy_kevsync.main.do_kev_sync", new=AsyncMock()
    ) as mock_do_kev_sync, patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(config_file=None, log_level="info"),
    ), patch(
        "logging.shutdown"
    ) as mock_logging_shutdown:

        await main_async()

        mock_do_kev_sync.assert_called_once_with(None, "info")
        mock_logging_shutdown.assert_called_once()


async def test_main_async_with_args():
    """Test the main_async function with arguments."""
    test_args = ["program", "--config-file", "test_config.yaml", "--log-level", "debug"]
    with patch.object(sys, "argv", test_args), patch(
        "cyhy_kevsync.main.do_kev_sync", new=AsyncMock()
    ) as mock_do_kev_sync, patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(
            config_file="test_config.yaml", log_level="debug"
        ),
    ), patch(
        "logging.shutdown"
    ) as mock_logging_shutdown:

        await main_async()

        mock_do_kev_sync.assert_called_once_with("test_config.yaml", "debug")
        mock_logging_shutdown.assert_called_once()


async def test_do_kev_sync_valid_config(capfd, db_uri, db_name):
    """Test the do_kev_sync function with a valid configuration."""
    valid_config = KEVSyncConfig(
        kevsync=KEVSync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url=DEFAULT_KEV_URL,
            log_level="info",
            schema_url=DEFAULT_KEV_SCHEMA_URL,
        )
    )
    with patch("cyhy_kevsync.main.get_config", return_value=valid_config):
        await do_kev_sync(config_file=None, arg_log_level=None)
    kev_sync_output = capfd.readouterr().out
    assert "Processing KEV feed" in kev_sync_output
    assert "KEV synchronization complete" in kev_sync_output


async def test_do_kev_sync_setup_logging(db_uri, db_name):
    """Test that do_kev_sync ignores the log_level in the config if it's set via arg_log_level."""
    valid_config = KEVSyncConfig(
        kevsync=KEVSync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url=DEFAULT_KEV_URL,
            log_level="info",
            schema_url=DEFAULT_KEV_SCHEMA_URL,
        )
    )
    with patch("cyhy_kevsync.main.get_config", return_value=valid_config):
        await do_kev_sync(config_file=None, arg_log_level="critical")
    assert (
        logging.getLogger(f"{CYHY_ROOT_LOGGER}.main").getEffectiveLevel()
        == logging.CRITICAL
    )


async def test_do_kev_sync_no_schema(capfd, db_uri, db_name):
    """Test that do_kev_sync skips schema validation if no schema is provided in the config."""
    valid_config = KEVSyncConfig(
        kevsync=KEVSync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url=DEFAULT_KEV_URL,
        )
    )
    with patch("cyhy_kevsync.main.get_config", return_value=valid_config):
        await do_kev_sync(config_file=None, arg_log_level="warning")
    kev_sync_output = capfd.readouterr().out
    assert "No schema URL provided" in kev_sync_output


async def test_do_kev_sync_invalid_config(capfd):
    """Test the do_kev_sync function with an invalid configuration file."""
    invalid_config = b'foo = "bar"'
    with patch("pathlib.Path.exists", return_value=True):
        with patch("os.path.isfile", return_value=True):
            with patch("builtins.open", mock_open(read_data=invalid_config)):
                with pytest.raises(SystemExit) as exc_info:
                    await do_kev_sync(config_file="mock_file", arg_log_level="debug")
                assert "validation error for KEVSyncConfig" in capfd.readouterr().out
                assert exc_info.value.code == 1, "Expected exit code 1"


async def test_do_kev_sync_file_not_found(capfd):
    """Test the do_kev_sync function with a missing configuration file."""
    with pytest.raises(SystemExit) as exc_info:
        await do_kev_sync(config_file="non-existent_file", arg_log_level="debug")
    assert "No CyHy configuration file found" in capfd.readouterr().out
    assert exc_info.value.code == 1, "Expected exit code 1"
