# Standard Python Libraries
import json
import logging
from typing import List, Optional
import urllib.request

# Third-Party Libraries
from beanie.operators import NotIn
from cyhy_db.models import KEVDoc
from jsonschema import SchemaError, ValidationError, validate
from rich.progress import track

ALLOWED_URL_SCHEMES = ["http", "https"]

logger = logging.getLogger(__name__)


async def fetch_kev_data(kev_json_url: str) -> dict:
    """
    Fetch the KEV data from the given URL and optionally validate it against a schema.

    This function retrieves the Known Exploited Vulnerabilities (KEV) JSON data from the specified URL.
    If a schema URL is provided, it validates the JSON data against the schema to ensure its integrity.

    Args:
        kev_json_url (str): The URL to fetch the KEV JSON data from.
        kev_schema_url (Optional[str]): The URL to fetch the KEV JSON schema from for validation (optional).

    Returns:
        dict: The KEV JSON data.

    Raises:
        ValueError: If the URL scheme is not allowed.
        Exception: If the KEV JSON or schema cannot be retrieved or if validation fails.
    """
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

    return kev_json


async def validate_kev_data(kev_json: dict, kev_schema_url: str) -> None:
    """
    Validate the KEV JSON data against the given schema.

    This function validates the Known Exploited Vulnerabilities (KEV) JSON data against the provided schema.
    It ensures that the JSON data conforms to the schema and raises an error if validation fails. The function
    also logs the validation process and any discrepancies found in the vulnerability counts.

    Args:
        kev_json (dict): The KEV JSON data containing vulnerability information.
        kev_schema_url (str): The URL to fetch the KEV JSON schema from for validation.

    Raises:
        ValueError: If the URL scheme is not allowed.
        Exception: If the KEV JSON schema cannot be retrieved or if validation fails.
    """
    # Create a Request object to test the safety of the URL
    key_schema_request = urllib.request.Request(kev_schema_url)
    if key_schema_request.type not in ALLOWED_URL_SCHEMES:
        raise ValueError(
            "Invalid URL scheme in schema URL: %s" % key_schema_request.type
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
            raise e
        except SchemaError as e:
            logger.error("The schema was not valid: %s", e.message)
            raise e

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


async def add_kev_docs(kev_json_feed: dict) -> List[KEVDoc]:
    """
    Process the KEV JSON data and create KEV documents.

    This function processes the KEV JSON data, extracts relevant information, and creates KEV documents.
    Each document is saved to the database and a list of created documents is returned.

    Args:
        kev_json_feed (dict): The KEV JSON data.

    Returns:
        List[KEVDoc]: A list of created KEV documents.

    Raises:
        ValueError: If the cveID is not found in the KEV JSON.
    """
    created_kev_docs: List[KEVDoc] = list()

    for kev_json in track(
        kev_json_feed["vulnerabilities"],
        description="Creating KEV docs",
    ):
        cve_id = kev_json.get("cveID")
        if not cve_id:
            raise ValueError("cveID not found in KEV JSON.")
        known_ransomware = kev_json["knownRansomwareCampaignUse"].lower() == "known"
        kev_doc = KEVDoc(id=cve_id, known_ransomware=known_ransomware)
        await kev_doc.save()
        logger.debug("Created KEV document with id: %s", cve_id)
        created_kev_docs.append(kev_doc)

    return created_kev_docs


async def remove_outdated_kev_docs(created_kev_docs: List[KEVDoc]) -> List[KEVDoc]:
    """
    Remove KEV documents that are no longer in the KEV JSON data.

    This function identifies and removes KEV documents that are no longer present in the latest KEV JSON data.
    It ensures that the database remains up-to-date by deleting outdated documents.

    Args:
        created_kev_docs (List[KEVDoc]): A list of KEV documents that were recently created.

    Returns:
        List[KEVDoc]: A list of removed KEV documents.
    """
    removed_kev_docs: List[KEVDoc] = list()

    # Extract the IDs of the created KEV docs
    created_kev_ids = {kev.id for kev in created_kev_docs}
    outdated_kev_docs = await KEVDoc.find(NotIn(KEVDoc.id, created_kev_ids)).to_list()

    for kev in track(outdated_kev_docs, description="Removing outdated KEV docs"):
        if kev not in created_kev_docs:
            await kev.delete()
            removed_kev_docs.append(kev)
            logger.debug("Removed outdated KEV document with id: %s", kev.id)
    return removed_kev_docs
