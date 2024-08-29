import json
import logging
import time
import random
import urllib.request

from rich.progress import track

from cyhy_db.models import KEVDoc

# TODO rename this file to something better

logger = logging.getLogger(__name__)

# def sync(url: str = DEFAULT_KEV_URL) -> None:
#     """Synchronize the KEV data from the given URL."""

#     for _ in track(
#         range(100),
#         description="KEV Syncing",
#     ):
#         time.sleep(random.uniform(0.01, 1))


async def fetch_kev_data(url: str) -> dict:
    """Fetch the KEV data from the given URL."""

    # We disable the bandit blacklist for the urllib.request.urlopen() function
    # because the URL is either the default (safe) URL or one provided in the
    # Lambda configuration so we can assume it is safe.
    with urllib.request.urlopen(url) as response:  # nosec B310
        if response.status != 200:
            raise Exception("Failed to retrieve KEV JSON.")

        kev_json = json.loads(response.read().decode("utf-8"))

    # TODO: Check the data against the schema
    # https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json

    # Sanity check the JSON data
    if "vulnerabilities" not in kev_json:
        raise ValueError(
            "JSON does not look like valid KEV data. Missing vulnerabilities."
        )

    reported_vuln_count = kev_json.get("count")
    if reported_vuln_count is None:
        raise ValueError("JSON does not look like valid KEV data.  Missing count.")

    actual_vuln_count = len(kev_json["vulnerabilities"])
    if reported_vuln_count != actual_vuln_count:
        logger.warning(
            "Reported vulnerability count (%d) does not match actual count (%d).",
            reported_vuln_count,
            actual_vuln_count,
        )
    else:
        logger.info(
            "Reported vulnerability count matches actual count: %d",
            actual_vuln_count,
        )

    return kev_json


async def create_kev_doc(kev_json: dict) -> str:
    """Add the provided KEV to the database and return its id."""
    cve_id = kev_json.get("cveID")
    if not cve_id:
        raise ValueError("JSON does not look like valid KEV data.")
    known_ransomware = kev_json.get("knownRansomwareCampaignUse").lower() == "known"
    kev_doc = KEVDoc(id=cve_id, known_ransomware=known_ransomware)
    await kev_doc.save()
    logger.debug("Created KEV document with id: %s", cve_id)
    return kev_doc.id


async def remove_outdated_kevs() -> None:
    """Remove KEVs that are no longer in the KEV JSON data."""
    # TODO implement this
    pass


async def process_kev_json(kev_json: dict) -> None:
    """Process the KEV JSON data."""
    for kev in kev_json["vulnerabilities"]:
        try:
            await create_kev_doc(kev)
        except Exception as e:
            logger.error("Failed to create KEV document: %s", e)
            continue  # TODO fail hard, or keep going?
