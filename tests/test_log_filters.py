# Standard Python Libraries
from io import StringIO
import logging

# Third-Party Libraries
import pytest

# cisagov Libraries
from cyhy_kevsync.log_filters import RedactPasswordFilter


@pytest.fixture
def logger():
    # Set up a logger for testing
    logger = logging.getLogger("test_logger")
    logger.setLevel(logging.INFO)

    # Create a string stream to capture logs
    log_stream = StringIO()
    handler = logging.StreamHandler(log_stream)
    logger.addHandler(handler)

    # Add the RedactPasswordFilter
    redact_filter = RedactPasswordFilter()
    logger.addFilter(redact_filter)

    yield logger, log_stream

    # Clean up
    logger.removeHandler(handler)
    logger.removeFilter(redact_filter)
    handler.close()


def test_redact_password_in_url(logger):
    logger, log_stream = logger
    logger.info(
        "Accessing the API at https://username:password@api.example.com/resource"
    )

    log_contents = log_stream.getvalue()
    assert "https://username:****@api.example.com/resource" in log_contents
    assert "password" not in log_contents


def test_redact_password_in_url_with_non_http_scheme(logger):
    logger, log_stream = logger
    logger.info("Connecting to ftp://user:secret@ftp.example.com/resource")

    log_contents = log_stream.getvalue()
    assert "ftp://user:****@ftp.example.com/resource" in log_contents
    assert "secret" not in log_contents


def test_no_password_in_url(logger):
    logger, log_stream = logger
    logger.info("Connecting to https://user@api.example.com/resource")

    log_contents = log_stream.getvalue()
    assert "https://user@api.example.com/resource" in log_contents
    assert "****" not in log_contents


def test_no_userinfo_in_url(logger):
    logger, log_stream = logger
    logger.info("Connecting to https://api.example.com/resource")

    log_contents = log_stream.getvalue()
    assert "https://api.example.com/resource" in log_contents
    assert "****" not in log_contents


def test_multiple_urls_in_message(logger):
    logger, log_stream = logger
    logger.info(
        "Check these URLs: https://user1:pass1@site1.com/resource and ftp://user2:pass2@site2.com/resource"
    )

    log_contents = log_stream.getvalue()
    assert "https://user1:****@site1.com/resource" in log_contents
    assert "ftp://user2:****@site2.com/resource" in log_contents
    assert "pass1" not in log_contents
    assert "pass2" not in log_contents


def test_no_url_in_message(logger):
    logger, log_stream = logger
    logger.info("This is a regular log message without a URL.")

    log_contents = log_stream.getvalue()
    assert "This is a regular log message without a URL." in log_contents


def test_partial_userinfo_in_url(logger):
    logger, log_stream = logger
    logger.info("Accessing the API at https://user:@api.example.com/resource")

    log_contents = log_stream.getvalue()
    assert "https://user:****@api.example.com/resource" in log_contents
    assert "user:@" not in log_contents  # Ensure the original userinfo is not present
    assert "****" in log_contents  # Ensure the password is redacted
