"""This module provides functions for fetching, validating, and synchronizing Known Exploited Vulnerabilities (KEV) data."""

# Standard Python Libraries
import json
import logging
from typing import Dict, List, Tuple
import urllib.request

# Third-Party Libraries
from cyhy_db.models import KEVDoc
from cyhy_logging import CYHY_ROOT_LOGGER
from jsonschema import SchemaError, ValidationError, validate
from rich.progress import track

ALLOWED_URL_SCHEMES = ["http", "https"]

logger = logging.getLogger(f"{CYHY_ROOT_LOGGER}.{__name__}")


async def fetch_kev_data(kev_json_url: str) -> dict:
    """
    Fetch the KEV data from the given URL.

    This function retrieves the Known Exploited Vulnerabilities (KEV) JSON data from the specified URL.

    Args:
        kev_json_url (str): The URL to fetch the KEV JSON data from.

    Returns:
        dict: The KEV JSON data.

    Raises:
        urllib.error.HTTPError: If the KEV JSON or schema cannot be retrieved or if validation fails.
        ValueError: If the URL scheme is not allowed.
    """
    # Create a Request object so we can test the safety of the URL
    kev_json_request = urllib.request.Request(kev_json_url)
    if kev_json_request.type not in ALLOWED_URL_SCHEMES:
        raise ValueError(
            "Invalid URL scheme in KEV JSON URL: %s" % kev_json_request.type
        )

    # Below we disable the bandit blacklist for the urllib.request.urlopen() function
    # since we are checking the URL scheme before using.

    with urllib.request.urlopen(kev_json_url) as response:  # nosec B310
        if response.status != 200:
            raise urllib.error.HTTPError(
                kev_json_url,
                response.status,
                "Failed to retrieve KEV JSON.",
                response.headers,
                None,
            )

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
        json.JSONDecodeError: If the response content is not valid JSON.
        jsonschema.exceptions.SchemaError: If the KEV JSON schema itself is not valid.
        jsonschema.exceptions.ValidationError: If the KEV JSON data does not conform to the schema.
        urllib.error.URLError: If there is an issue with retrieving the KEV schema (e.g., HTTP error).
        ValueError: If the URL scheme is not allowed.
    """
    # Create a Request object to test the safety of the URL
    kev_schema_request = urllib.request.Request(kev_schema_url)
    if kev_schema_request.type not in ALLOWED_URL_SCHEMES:
        raise ValueError(
            "Invalid URL scheme in KEV schema URL: %s" % kev_schema_request.type
        )
    with urllib.request.urlopen(kev_schema_url) as response:  # nosec B310
        if response.status != 200:
            raise urllib.error.HTTPError(
                kev_schema_url,
                response.status,
                "Failed to retrieve KEV JSON schema.",
                response.headers,
                None,
            )

        try:
            kev_schema = json.loads(response.read().decode("utf-8"))
        except json.JSONDecodeError as e:
            logger.error("Failed to decode KEV JSON schema: %s", e.msg)
            raise e

        try:
            validate(instance=kev_json, schema=kev_schema)
            logger.info("KEV JSON is valid against the schema.")
        except ValidationError as e:
            logger.error("KEV JSON data does not conform to the schema: %s", e.message)
            raise e
        except SchemaError as e:
            logger.error("The JSON schema was not valid: %s", e.message)
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


async def sync_kev_docs(
    kev_json_feed: dict,
) -> Tuple[List[KEVDoc], List[KEVDoc], List[KEVDoc]]:
    """
    Synchronize KEV documents with the latest KEV JSON data.

    This function processes the KEV JSON data, updates the database by adding new KEV documents,
    updating existing ones, and removing outdated ones. It ensures that the database contains the
    most up-to-date KEV documents.

    Args:
        kev_json_feed (dict): The KEV JSON data containing vulnerability information.

    Returns:
        Tuple[List[KEVDoc], List[KEVDoc], List[KEVDoc]]:
            - List created KEV documents.
            - List updated KEV documents.
            - List deleted KEV documents.
    """
    created_kev_docs: List[KEVDoc] = []
    deleted_kev_docs: List[KEVDoc] = []
    updated_kev_docs: List[KEVDoc] = []

    # Fetch all existing KEV documents from the database
    kev_map: Dict[str, KEVDoc] = {
        str(kev.id): kev for kev in await KEVDoc.find_all().to_list()
    }

    # Process each vulnerability in the KEV JSON feed
    for kev_json in track(
        kev_json_feed["vulnerabilities"],
        description="Processing KEV feed",
    ):
        cve_id = kev_json.get("cveID")
        known_ransomware = kev_json["knownRansomwareCampaignUse"].lower() == "known"
        kev_doc = kev_map.pop(cve_id, None)

        if kev_doc:  # Update existing KEV doc
            if kev_doc.known_ransomware != known_ransomware:
                kev_doc.known_ransomware = known_ransomware
                await kev_doc.save()
                logger.info("Updated KEV document with id: %s", cve_id)
                updated_kev_docs.append(kev_doc)
        else:  # Create new KEV doc
            kev_doc = KEVDoc(id=cve_id, known_ransomware=known_ransomware)
            await kev_doc.save()
            logger.info("Created KEV document with id: %s", cve_id)
            created_kev_docs.append(kev_doc)

    # Delete unseen KEV docs
    for kev_doc in track(kev_map.values(), description="Deleting KEV docs"):
        await kev_doc.delete()
        logger.info("Deleted KEV document with id: %s", kev_doc.id)
        deleted_kev_docs.append(kev_doc)

    return created_kev_docs, updated_kev_docs, deleted_kev_docs
