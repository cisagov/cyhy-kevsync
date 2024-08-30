"""Test database connection."""

# Third-Party Libraries
from cyhy_db.models import KEVDoc
from jsonschema import ValidationError
from motor.motor_asyncio import AsyncIOMotorClient
import pytest

# cisagov Libraries
from cyhy_kevsync import DEFAULT_KEV_SCHEMA_URL, DEFAULT_KEV_URL
from cyhy_kevsync.kev_sync import fetch_kev_data, sync_kev_docs, validate_kev_data

CVE_1 = "CVE-2024-123456"
VULN_1 = {"cveID": CVE_1, "knownRansomwareCampaignUse": "Known"}


async def test_connection_motor(db_uri, db_name):
    client = AsyncIOMotorClient(db_uri)
    db = client[db_name]
    server_info = await db.command("ping")
    assert server_info["ok"] == 1.0, "Direct database ping failed"


async def test_fetch_kev_data():
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL)
    assert "vulnerabilities" in kev_json_feed, "Expected 'vulnerabilities' in KEV data"
    assert (
        len(kev_json_feed["vulnerabilities"]) > 0
    ), "Expected at least one vulnerability item in KEV data"


async def test_validate_kev_data_good():
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL)
    await validate_kev_data(kev_json_feed, DEFAULT_KEV_SCHEMA_URL)


async def test_validate_kev_data_bad():
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL)
    # mangle the data
    kev_json_feed["yourmom"] = kev_json_feed.pop("vulnerabilities")

    with pytest.raises(ValidationError):
        await validate_kev_data(kev_json_feed, DEFAULT_KEV_SCHEMA_URL)


async def test_sync_kev_docs():
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL)
    # Trim the data to 20 items
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
