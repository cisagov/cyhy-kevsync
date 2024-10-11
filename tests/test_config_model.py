"""Tests for the KEVSync configuration model."""

# Third-Party Libraries
from pydantic import ValidationError
import pytest

# cisagov Libraries
from cyhy_kevsync.models.config_model import (
    DEFAULT_KEV_SCHEMA_URL,
    DEFAULT_KEV_URL,
    KEVSync,
)


def test_set_json_url_and_schema_url():
    """Test setting both the JSON and schema URLs."""
    config = KEVSync(
        db_auth_uri="mongodb://localhost:27017",
        db_name="test_db",
        json_url="https://example.gov/kev.json",
        schema_url="https://example.gov/schema.json",
    )
    assert config.json_url == "https://example.gov/kev.json"
    assert config.schema_url == "https://example.gov/schema.json"


def test_set_json_url_without_schema_url():
    """Test setting the JSON URL without setting a schema URL."""
    config = KEVSync(
        db_auth_uri="mongodb://localhost:27017",
        db_name="test_db",
        json_url="https://example.gov/kev.json",
    )
    assert config.json_url == "https://example.gov/kev.json"
    assert config.schema_url is None


def test_set_schema_url_without_json_url():
    """Test setting the schema URL without setting the JSON URL."""
    config = KEVSync(
        db_auth_uri="mongodb://localhost:27017",
        db_name="test_db",
        schema_url="https://example.gov/schema.json",
    )
    assert config.json_url == DEFAULT_KEV_URL
    assert config.schema_url == "https://example.gov/schema.json"


def test_default_json_and_schema_urls():
    """Test the default JSON and schema URLs."""
    config = KEVSync(
        db_auth_uri="mongodb://localhost:27017",
        db_name="test_db",
    )
    assert config.json_url == DEFAULT_KEV_URL
    assert config.schema_url == DEFAULT_KEV_SCHEMA_URL


def test_invalid_db_auth_uri():
    """Test an invalid database authentication URI."""
    with pytest.raises(ValidationError):
        KEVSync(db_auth_uri="invalid_uri", db_name="test_db")


def test_invalid_json_url():
    """Test an invalid JSON URL."""
    with pytest.raises(ValidationError):
        KEVSync(
            db_auth_uri="mongodb://localhost:27017",
            db_name="test_db",
            json_url="invalid_url",
        )


def test_invalid_schema_url():
    """Test an invalid schema URL."""
    with pytest.raises(ValidationError):
        KEVSync(
            db_auth_uri="mongodb://localhost:27017",
            db_name="test_db",
            schema_url="invalid_url",
        )
