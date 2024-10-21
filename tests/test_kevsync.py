"""Test database connection."""

# Standard Python Libraries
import json
import os
from unittest.mock import Mock, patch
import urllib.error

# Third-Party Libraries
from cyhy_db.models import KEVDoc
import jsonschema
from motor.motor_asyncio import AsyncIOMotorClient
import pytest

# cisagov Libraries
from cyhy_kevsync import DEFAULT_KEV_SCHEMA_URL, DEFAULT_KEV_URL, __version__
from cyhy_kevsync.kev_sync import fetch_kev_data, sync_kev_docs, validate_kev_data

# Sample data
VALID_KEV_JSON = {
    "catalogVersion": "2024.10.17",
    "dateReleased": "2024-10-17T14:50:49.2815Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-40711",
            "vendorProject": "Veeam",
            "product": "Backup & Replication",
            "vulnerabilityName": "Deserialization Vulnerability",
            "dateAdded": "2024-10-17",
            "shortDescription": "A description",
            "requiredAction": "Apply mitigations",
            "dueDate": "2024-11-07",
            "cwes": ["CWE-502"],
        },
        {
            "cveID": "CVE-2024-28987",
            "vendorProject": "SolarWinds",
            "product": "Web Help Desk",
            "vulnerabilityName": "Hardcoded Credential Vulnerability",
            "dateAdded": "2024-10-15",
            "shortDescription": "Another description",
            "requiredAction": "Apply mitigations",
            "dueDate": "2024-11-05",
            "cwes": ["CWE-798"],
        },
    ],
}

VALID_KEV_JSON_SCHEMA = b"""{
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "catalogVersion": {"type": "string"},
            "dateReleased": {"type": "string", "format": "date-time"},
            "count": {"type": "integer"},
            "vulnerabilities": {"type": "array"}
        },
        "required": ["catalogVersion", "dateReleased", "count", "vulnerabilities"]
    }"""

# define sources of version strings
RELEASE_TAG = os.getenv("RELEASE_TAG")
PROJECT_VERSION = __version__


@pytest.mark.skipif(
    RELEASE_TAG in [None, ""], reason="this is not a release (RELEASE_TAG not set)"
)
def test_release_version():
    """Verify that release tag version agrees with the module version."""
    assert (
        RELEASE_TAG == f"v{PROJECT_VERSION}"
    ), "RELEASE_TAG does not match the project version"


async def test_connection_motor(db_uri, db_name):
    """Test the database connection."""
    client = AsyncIOMotorClient(db_uri)
    db = client[db_name]
    server_info = await db.command("ping")
    assert server_info["ok"] == 1.0, "Direct database ping failed"


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_fetch_kev_data_success(mock_urlopen):
    """Test fetching KEV data successfully."""
    # Mocking the successful response
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = (
        b'{"catalogVersion": "2024.10.17", "vulnerabilities": []}'
    )
    mock_urlopen.return_value.__enter__.return_value = mock_response

    kev_data = await fetch_kev_data(DEFAULT_KEV_URL)

    assert kev_data == {"catalogVersion": "2024.10.17", "vulnerabilities": []}


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_fetch_kev_data_invalid_url_scheme(mock_urlopen):
    """Test fetching KEV data with an invalid URL scheme."""
    kev_json_url = "ftp://example.com/kev.json"

    with pytest.raises(ValueError, match="Invalid URL scheme in KEV JSON URL: ftp"):
        await fetch_kev_data(kev_json_url)


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_fetch_kev_data_json_decode_error(mock_urlopen):
    """Test fetching KEV data with a JSON decode error."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = b"Invalid JSON"
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(json.JSONDecodeError):
        await fetch_kev_data(DEFAULT_KEV_URL)


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_fetch_kev_data_non_200_response(mock_urlopen):
    """Test fetching KEV data with a non-200 HTTP response."""
    mock_response = Mock()
    mock_response.status = 500
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(Exception, match="Failed to retrieve KEV JSON."):
        await fetch_kev_data(DEFAULT_KEV_URL)


async def test_fetch_real_kev_data():
    """Test fetching KEV data."""
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL)
    assert "vulnerabilities" in kev_json_feed, "Expected 'vulnerabilities' in KEV data"
    assert (
        len(kev_json_feed["vulnerabilities"]) > 0
    ), "Expected at least one vulnerability item in KEV data"


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_validate_kev_data_good(mock_urlopen):
    """Test validating KEV data successfully."""
    # Mocking the schema response
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = VALID_KEV_JSON_SCHEMA
    mock_urlopen.return_value.__enter__.return_value = mock_response

    await validate_kev_data(VALID_KEV_JSON, DEFAULT_KEV_SCHEMA_URL)


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_validate_kev_data_invalid_schema(mock_urlopen):
    """Test validation fails when schema is invalid."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = b"""{
        "type": "invalid"
    }"""  # Invalid schema
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(jsonschema.exceptions.SchemaError):
        await validate_kev_data(VALID_KEV_JSON, "https://example.com/schema.json")


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_validate_kev_data_invalid_scheme(mock_urlopen):
    """Test fetching KEV data with an invalid URL scheme."""
    bad_kev_json_schema_url = "ftp://example.com/kev-schema.json"

    with pytest.raises(ValueError, match="Invalid URL scheme in KEV schema URL: ftp"):
        await validate_kev_data(VALID_KEV_JSON, bad_kev_json_schema_url)


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_validate_kev_data_missing_field(mock_urlopen):
    """Test validation fails for missing required field."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = VALID_KEV_JSON_SCHEMA
    mock_urlopen.return_value.__enter__.return_value = mock_response

    invalid_kev_json = VALID_KEV_JSON.copy()
    del invalid_kev_json["count"]  # Remove a required field

    with pytest.raises(jsonschema.exceptions.ValidationError):
        await validate_kev_data(invalid_kev_json, DEFAULT_KEV_SCHEMA_URL)


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_validate_kev_data_non_200_response(mock_urlopen):
    """Test validating KEV data with a non-200 HTTP response."""
    # Mocking a valid response that is not 200 (e.g., 404 Not Found)
    mock_response = Mock()
    mock_response.status = 404
    mock_response.read.return_value = b""  # No content needed for this error
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Ensure that an HTTPError is raised due to the non-200 response
    with pytest.raises(
        urllib.error.HTTPError, match="Failed to retrieve KEV JSON schema."
    ):
        await validate_kev_data(VALID_KEV_JSON, DEFAULT_KEV_SCHEMA_URL)


@pytest.mark.asyncio
@patch("urllib.request.urlopen")
async def test_validate_kev_data_json_decode_error(mock_urlopen):
    """Test validating KEV data with a JSON decode error."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = b"Invalid JSON"  # Non-JSON response
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(json.JSONDecodeError):
        await validate_kev_data(VALID_KEV_JSON, DEFAULT_KEV_SCHEMA_URL)


@pytest.mark.asyncio
@patch("cyhy_kevsync.kev_sync.logger")
@patch("urllib.request.urlopen")
async def test_validate_kev_data_count_mismatch(mock_urlopen, mock_logger):
    """Test validating KEV data when the reported count does not match the actual count."""
    # Mocking the successful schema response
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = VALID_KEV_JSON_SCHEMA
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Create KEV JSON data with mismatched count
    bad_kev_json = VALID_KEV_JSON.copy()
    bad_kev_json["count"] -= 1

    await validate_kev_data(bad_kev_json, DEFAULT_KEV_SCHEMA_URL)

    # Check that the warning was logged
    real_vuln_count = len(bad_kev_json["vulnerabilities"])
    mock_logger.warning.assert_called_once_with(
        "Reported vulnerability count (%d) does not match actual count (%d).",
        bad_kev_json["count"],
        real_vuln_count,
    )


async def test_sync_kev_docs():
    """Test synchronizing KEV documents."""
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL)
    # Trim the data to 40 items
    kev_json_feed["vulnerabilities"] = kev_json_feed["vulnerabilities"][:40]

    # Check the count before processing
    before_count = await KEVDoc.count()
    created_kev_docs, updated_kev_docs, deleted_kev_docs = await sync_kev_docs(
        kev_json_feed
    )
    # Check the count of KEV documents in the database
    after_count = await KEVDoc.count()
    assert after_count > before_count, "Expected more KEV documents after processing"
    # Check that the returned list is correct
    assert len(created_kev_docs) == len(
        kev_json_feed["vulnerabilities"]
    ), "Expected same number of KEV documents as in the KEV data"

    # Delete some of the KEV documents
    for kev_doc in created_kev_docs[:11]:
        await kev_doc.delete()
    # Modify some of the existing KEV documents
    for kev_doc in created_kev_docs[12:25]:
        kev_doc.known_ransomware = not kev_doc.known_ransomware
        await kev_doc.save()
    # Create new KEV documents
    for kev_json in kev_json_feed["vulnerabilities"][:17]:
        cve_id = kev_json.get("cveID")
        known_ransomware = kev_json["knownRansomwareCampaignUse"].lower() == "known"
        kev_doc = KEVDoc(id=cve_id + "_bogus", known_ransomware=known_ransomware)
        await kev_doc.save()
    # Rerun the sync
    created_kev_docs, updated_kev_docs, deleted_kev_docs = await sync_kev_docs(
        kev_json_feed
    )
    # Check that the returned list is correct
    assert len(created_kev_docs) == 11, "Documents not re-created"
    assert len(updated_kev_docs) == 13, "Documents not reverted"
    assert len(deleted_kev_docs) == 17, "Documents not deleted"
