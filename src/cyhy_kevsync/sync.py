# Standard Python Libraries
import json
import logging
from typing import Optional
import urllib.request

# Third-Party Libraries
from cyhy_db.models import KEVDoc
from jsonschema import SchemaError, ValidationError, validate
from rich.progress import track

# TODO rename this file to something better

ALLOWED_URL_SCHEMES = ["http", "https"]

logger = logging.getLogger(__name__)


async def fetch_kev_data(
    kev_json_url: str, kev_schema_url: Optional[str] = None
) -> dict:
    """Fetch the KEV data from the given URL."""

    # Create a Request object so we can test the safety of the URL
    key_json_request = urllib.request.Request(kev_json_url)
    if key_json_request.type not in ALLOWED_URL_SCHEMES:
        raise ValueError("Invalid URL scheme in json URL: %s" % key_json_request.type)

    # Below we disable the bandit blacklist for the urllib.request.urlopen() function
    # since we are checking the URL scheme before using.

    with urllib.request.urlopen(kev_json_url) as response:  # nosec B310
        if response.status != 200:
            raise Exception("Failed to retrieve KEV JSON.")

        kev_json = json.loads(response.read().decode("utf-8"))

    # If a schema URL was provided, we will validate the JSON data against it
    if kev_schema_url:
        # Create a Request object so we can test the safety of the URL
        key_schema_request = urllib.request.Request(kev_schema_url)
        if key_schema_request.type not in ALLOWED_URL_SCHEMES:
            raise ValueError(
                "Invalid URL scheme in schema URL: %s" % key_json_request.type
            )
        with urllib.request.urlopen(kev_schema_url) as response:  # nosec B310
            if response.status != 200:
                raise Exception("Failed to retrieve KEV JSON schema.")
            kev_schema = json.loads(response.read().decode("utf-8"))
            try:
                validate(instance=kev_json, schema=kev_schema)
                logger.info("KEV JSON is valid against the schema.")
            except ValidationError as e:
                logger.error("JSON validation error: %s", e.message)
            except SchemaError as e:
                logger.error("Schema error: %s", e.message)

    reported_vuln_count = kev_json.get("count")
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
        raise ValueError("cveID not found in KEV JSON.")
    known_ransomware = kev_json["knownRansomwareCampaignUse"].lower() == "known"
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
    for kev in track(
        kev_json["vulnerabilities"],
        description="Creating KEV docs",
    ):
        try:
            await create_kev_doc(kev)
        except Exception as e:
            logger.error("Failed to create KEV document: %s", e)
            continue  # TODO fail hard, or keep going?
