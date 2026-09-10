"""Regression tests for duplicate CVE identifiers in a KEV feed."""

# Standard Python Libraries
from copy import deepcopy

# Third-Party Libraries
from cyhy_db.models import KEVDoc
import pytest

# cisagov Libraries
from cyhy_kevsync.kev_sync import sync_kev_docs

pytestmark = pytest.mark.usefixtures("empty_kevs")


@pytest.fixture
async def empty_kevs(db_client):
    """Isolate synthetic KEV records inside the existing test database."""
    await KEVDoc.delete_all()
    yield
    await KEVDoc.delete_all()


async def saved_state():
    """Return only the persisted fields relevant to synchronization."""
    return {
        str(doc.id): doc.known_ransomware
        for doc in await KEVDoc.find_all().to_list()
    }


@pytest.mark.parametrize("duplicate_id", ["CVE-2026-1001", "CVE-2026-2001"])
@pytest.mark.parametrize("second_status", ["Unknown", "Known"])
async def test_duplicate_feed_rejected_before_writes(
    duplicate_id, second_status
):
    """Reject identical and conflicting duplicates before any partial changes."""
    await KEVDoc(id="CVE-2026-1001", known_ransomware=False).save()
    await KEVDoc(id="CVE-2026-1002", known_ransomware=True).save()
    before = await saved_state()
    feed = {
        "vulnerabilities": [
            {"cveID": "CVE-2026-1002", "knownRansomwareCampaignUse": "Unknown"},
            {"cveID": duplicate_id, "knownRansomwareCampaignUse": "Unknown"},
            {"cveID": "CVE-2026-2002", "knownRansomwareCampaignUse": "Known"},
            {
                "cveID": duplicate_id,
                "knownRansomwareCampaignUse": second_status,
            },
        ]
    }
    original = deepcopy(feed)

    with pytest.raises(
        ValueError, match=f"Duplicate CVE ID in KEV feed: {duplicate_id}"
    ):
        await sync_kev_docs(feed)

    assert await saved_state() == before
    assert feed == original


async def test_unique_feed_keeps_create_update_delete_behavior():
    """Valid feeds retain the existing synchronization and result semantics."""
    await KEVDoc(id="CVE-2026-1001", known_ransomware=False).save()
    await KEVDoc(id="CVE-2026-1002", known_ransomware=True).save()
    created, updated, deleted = await sync_kev_docs(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1001",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2026-2001",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ]
        }
    )
    assert [doc.id for doc in created] == ["CVE-2026-2001"]
    assert [doc.id for doc in updated] == ["CVE-2026-1001"]
    assert [doc.id for doc in deleted] == ["CVE-2026-1002"]
    assert await saved_state() == {
        "CVE-2026-1001": True,
        "CVE-2026-2001": False,
    }


async def test_empty_feed_retains_existing_deletion_behavior():
    """The duplicate check must not change the handling of an empty feed."""
    await KEVDoc(id="CVE-2026-1001", known_ransomware=False).save()
    created, updated, deleted = await sync_kev_docs({"vulnerabilities": []})
    assert created == []
    assert updated == []
    assert [doc.id for doc in deleted] == ["CVE-2026-1001"]
    assert await saved_state() == {}
