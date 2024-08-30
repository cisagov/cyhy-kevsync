"""Model definitions for the configuration."""

# Standard Python Libraries
from typing import Optional

# Third-Party Libraries
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .. import DEFAULT_KEV_SCHEMA_URL, DEFAULT_KEV_URL


class KEVSync(BaseModel):
    """Definition of a KEV Sync configuration."""

    model_config = ConfigDict(extra="forbid")

    db_auth_uri: str = Field(
        pattern=r"^mongodb://", description="MongoDB connection URI"
    )
    db_name: str = Field(description="MongoDB database name")
    json_url: Optional[str] = Field(
        pattern=r"^https?://",
        default=DEFAULT_KEV_URL,
        description="URL to the KEV JSON file",
    )
    schema_url: Optional[str] = Field(
        None,
        pattern=r"^https?://",
        description="URL to the KEV JSON schema file",
    )

    @model_validator(mode="before")
    def set_default_schema_url(cls, values):
        """
        Set the schema_url to DEFAULT_KEV_SCHEMA_URL if json_url is not supplied.

        This validator checks if the json_url is not provided and sets the schema_url
        to DEFAULT_KEV_SCHEMA_URL if it is not already set.
        """
        if not values.get("json_url"):
            values["schema_url"] = values.get("schema_url", DEFAULT_KEV_SCHEMA_URL)
        return values


class KEVSyncConfig(BaseModel):
    """Definition of the KEVSync configuration root."""

    model_config = ConfigDict(extra="ignore")

    kevsync: KEVSync
