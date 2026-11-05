"""Test the main module."""

# Standard Python Libraries
import logging
import sys
from unittest.mock import AsyncMock, call, mock_open, patch

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
    with (
        patch.object(sys, "argv", test_args),
        patch("cyhy_kevsync.main.do_kev_sync", new=AsyncMock()) as mock_do_kev_sync,
        patch("logging.shutdown") as mock_logging_shutdown,
    ):

        await main_async()

        mock_do_kev_sync.assert_called_once_with(None, None)
        mock_logging_shutdown.assert_called_once()


async def test_main_async_with_args():
    """Test the main_async function with arguments."""
    test_args = ["program", "--config-file", "test_config.yaml", "--log-level", "debug"]
    with (
        patch.object(sys, "argv", test_args),
        patch("cyhy_kevsync.main.do_kev_sync", new=AsyncMock()) as mock_do_kev_sync,
        patch("logging.shutdown") as mock_logging_shutdown,
    ):

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
    """Test that log_level arg overrides value in config."""
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
    """Test that do_kev_sync skips schema validation if no schema is provided."""
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


@pytest.mark.parametrize(
    "cli_args,config_level,expected_levels",
    [
        ([], "debug", ["info", "debug"]),
        ([], "warning", ["info", "warning"]),
        ([], None, ["info"]),
        (["--log-level", "info"], "debug", ["info"]),
        (["-l", "critical"], "warning", ["critical"]),
    ],
)
async def test_main_async_log_level_precedence(cli_args, config_level, expected_levels):
    """CLI overrides config, config overrides the info fallback."""
    config = KEVSyncConfig(
        kevsync=KEVSync(
            db_auth_uri="mongodb://localhost:27017",
            db_name="test",
            log_level=config_level,
        )
    )
    with (
        patch.object(sys, "argv", ["cyhy-kevsync", *cli_args]),
        patch("cyhy_kevsync.main.get_config", return_value=config),
        patch("cyhy_kevsync.main.setup_logging") as mock_setup_logging,
        patch("cyhy_kevsync.main.initialize_db", new_callable=AsyncMock),
        patch("cyhy_kevsync.kev_sync.fetch_kev_data", new_callable=AsyncMock),
        patch("cyhy_kevsync.kev_sync.validate_kev_data", new_callable=AsyncMock),
        patch(
            "cyhy_kevsync.kev_sync.sync_kev_docs",
            new_callable=AsyncMock,
            return_value=([], [], []),
        ),
        patch("logging.shutdown"),
    ):
        await main_async()

    assert mock_setup_logging.call_args_list == [
        call(level) for level in expected_levels
    ]
