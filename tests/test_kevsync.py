"""Test database connection."""

# Third-Party Libraries
from motor.motor_asyncio import AsyncIOMotorClient

# cisagov Libraries
from cyhy_kevsync import DEFAULT_KEV_URL
from cyhy_kevsync.sync import fetch_kev_data, create_kev_doc, process_kev_json
from cyhy_db.models import KEVDoc

CVE_1 = "CVE-2024-123456"
VULN_1 = {"cveID": CVE_1, "knownRansomwareCampaignUse": "Known"}


async def test_connection_motor(db_uri, db_name):
    client = AsyncIOMotorClient(db_uri)
    db = client[db_name]
    server_info = await db.command("ping")
    assert server_info["ok"] == 1.0, "Direct database ping failed"


async def test_fetch_kev_data():
    kev_data = await fetch_kev_data(DEFAULT_KEV_URL)
    assert "vulnerabilities" in kev_data, "Expected 'vulnerabilities' in KEV data"
    assert (
        len(kev_data["vulnerabilities"]) > 0
    ), "Expected at least one vulnerability item in KEV data"


async def test_create_kev_doc():
    await create_kev_doc(VULN_1)
    # Attempt to find the newly created document
    kev: KEVDoc = await KEVDoc.get(CVE_1)
    assert KEVDoc is not None, "Expected document to be found in the database"
    assert kev.id == CVE_1, "Expected document to have the correct ID"


async def test_remove_outdated_kevs():
    # TODO implement this
    pass


async def test_process_kev_json():
    kev_data = await fetch_kev_data(DEFAULT_KEV_URL)
    # Check the count before processing
    before_count = await KEVDoc.count()
    await process_kev_json(kev_data)
    # Check the count of KEV documents in the database
    after_count = await KEVDoc.count()
    assert after_count > before_count, "Expected more KEV documents after processing"
