"""Test __main__.py."""

# Standard Python Libraries
import sys
from unittest.mock import patch

# Third-Party Libraries
import pytest


def test_main_called():
    """Test that the code in src/__main__.py is executed correctly."""
    test_args = ["cyhy-kevsync", "--help"]
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit) as exc_info:
            with patch("cyhy_kevsync.__main__.main") as mock_main:
                mock_main.assert_called_once()
        assert exc_info.value.code == 0
