"""Test database connection."""

# Third-Party Libraries
from cyhy_db.models import KEVDoc
from motor.motor_asyncio import AsyncIOMotorClient

# cisagov Libraries
from cyhy_kevsync import DEFAULT_KEV_SCHEMA_URL, DEFAULT_KEV_URL
from cyhy_kevsync.kev_sync import add_kev_docs, fetch_kev_data, remove_outdated_kev_docs

CVE_1 = "CVE-2024-123456"
VULN_1 = {"cveID": CVE_1, "knownRansomwareCampaignUse": "Known"}


async def test_connection_motor(db_uri, db_name):
    client = AsyncIOMotorClient(db_uri)
    db = client[db_name]
    server_info = await db.command("ping")
    assert server_info["ok"] == 1.0, "Direct database ping failed"


async def test_fetch_kev_data_without_schema():
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL, DEFAULT_KEV_SCHEMA_URL)
    assert "vulnerabilities" in kev_json_feed, "Expected 'vulnerabilities' in KEV data"
    assert (
        len(kev_json_feed["vulnerabilities"]) > 0
    ), "Expected at least one vulnerability item in KEV data"


async def test_fetch_kev_data_with_schema():
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL, DEFAULT_KEV_SCHEMA_URL)
    assert "vulnerabilities" in kev_json_feed, "Expected 'vulnerabilities' in KEV data"
    assert (
        len(kev_json_feed["vulnerabilities"]) > 0
    ), "Expected at least one vulnerability item in KEV data"


async def test_add_kev_docs():
    kev_json_feed = await fetch_kev_data(DEFAULT_KEV_URL, DEFAULT_KEV_SCHEMA_URL)
    # Check the count before processing
    before_count = await KEVDoc.count()
    created_kev_docs = await add_kev_docs(kev_json_feed)
    # Check the count of KEV documents in the database
    after_count = await KEVDoc.count()
    assert after_count > before_count, "Expected more KEV documents after processing"
    # Check that the returned list is correct
    assert len(created_kev_docs) == len(
        kev_json_feed["vulnerabilities"]
    ), "Expected same number of KEV documents as in the KEV data"
    # Check the types of the returned list
    assert all(
        isinstance(kev_doc, KEVDoc) for kev_doc in created_kev_docs
    ), "Expected all KEV documents in the list to be of type KEVDoc"


async def test_remove_outdated_kevs():
    # Check the count before processing
    before_count = await KEVDoc.count()
    removed_kev_docs = await remove_outdated_kev_docs(list())
    # Check the count of KEV documents in the database
    after_count = await KEVDoc.count()
    assert after_count < before_count, "Expected less KEV documents after processing"
