"""Model definitions for the configuration."""

# Standard Python Libraries
from typing import Optional

# Third-Party Libraries
from pydantic import BaseModel, ConfigDict, Field

from .. import DEFAULT_KEV_URL


class KEVSync(BaseModel):
    """Definition of an KEV Sync configuration."""

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


class KEVSyncConfig(BaseModel):
    """Definition of the KEVSync configuration root."""

    model_config = ConfigDict(extra="ignore")

    kevsync: KEVSync
