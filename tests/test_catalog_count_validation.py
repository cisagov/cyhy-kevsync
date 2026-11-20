"""Inconsistent catalog counts must stop validated KEV synchronization."""

# Standard Python Libraries
from copy import deepcopy
import importlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party Libraries
from jsonschema import ValidationError

# cisagov Libraries
from cyhy_kevsync import kev_sync

main = importlib.import_module("cyhy_kevsync.main")
SCHEMA = {
    "type": "object",
    "properties": {"count": {"type": "integer"}, "vulnerabilities": {"type": "array"}},
    "required": ["count", "vulnerabilities"],
}
SCHEMA_URL = "https://catalog.example/schema.json"


def schema_response():
    """Return a local schema without contacting any endpoint."""
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.read.return_value = json.dumps(SCHEMA).encode()
    return response


class CatalogCountValidationTest(unittest.IsolatedAsyncioTestCase):
    """Exercise real schema validation and the synchronization entry point."""

    async def test_mismatched_counts_are_rejected_without_mutating_input(self):
        """An inconsistent declaration never counts as validated data."""
        for declared, actual in [(2, 1), (2, 0), (0, 1), (1, 2)]:
            with self.subTest(declared=declared, actual=actual):
                feed = {
                    "count": declared,
                    "vulnerabilities": [{} for _ in range(actual)],
                }
                original = deepcopy(feed)
                with patch.object(
                    kev_sync.urllib.request, "urlopen", return_value=schema_response()
                ):
                    with self.assertRaisesRegex(ValueError, "count"):
                        await kev_sync.validate_kev_data(feed, SCHEMA_URL)
                self.assertEqual(feed, original)

    async def test_matching_counts_including_explicit_empty_catalogs_pass(self):
        """A deliberate, internally consistent empty catalog remains valid."""
        for count in [0, 1, 3]:
            with self.subTest(count=count):
                feed = {"count": count, "vulnerabilities": [{} for _ in range(count)]}
                with patch.object(
                    kev_sync.urllib.request, "urlopen", return_value=schema_response()
                ):
                    await kev_sync.validate_kev_data(feed, SCHEMA_URL)

    async def test_schema_failures_keep_their_existing_exception(self):
        """Schema-level validation still runs before count comparison."""
        with patch.object(
            kev_sync.urllib.request, "urlopen", return_value=schema_response()
        ):
            with self.assertRaises(ValidationError):
                await kev_sync.validate_kev_data({"vulnerabilities": []}, SCHEMA_URL)

    async def run_entry_point(self, feed):
        """Run orchestration with database and network boundaries mocked."""
        config = SimpleNamespace(
            kevsync=SimpleNamespace(
                log_level=None,
                db_auth_uri="mongodb://unused",
                db_name="unused",
                json_url="https://catalog.example/feed.json",
                schema_url=SCHEMA_URL,
            )
        )
        sync = AsyncMock(return_value=([], [], []))
        with (
            patch.object(main, "get_config", return_value=config),
            patch.object(main, "setup_logging"),
            patch.object(main, "initialize_db", new_callable=AsyncMock),
            patch.object(kev_sync, "fetch_kev_data", new=AsyncMock(return_value=feed)),
            patch.object(
                kev_sync.urllib.request, "urlopen", return_value=schema_response()
            ),
            patch.object(kev_sync, "sync_kev_docs", new=sync),
        ):
            try:
                await main.do_kev_sync()
            except ValueError:
                sync.assert_not_awaited()
                raise
        return sync

    async def test_incomplete_feed_cannot_reach_document_synchronization(self):
        """The normal validated path never enters deletion after a mismatch."""
        with self.assertRaisesRegex(ValueError, "count"):
            await self.run_entry_point({"count": 2, "vulnerabilities": []})

    async def test_validated_matching_feed_reaches_normal_synchronization(self):
        """The main entry point continues to synchronize consistent catalogs."""
        feed = {"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-1001"}]}
        sync = await self.run_entry_point(feed)
        sync.assert_awaited_once_with(feed)


if __name__ == "__main__":
    unittest.main()
