"""Model definitions for the configuration."""

# Standard Python Libraries
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

# Third-Party Libraries
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .. import DEFAULT_KEV_URL


class KEVSync(BaseModel):
    """Definition of an KEV Sync configuration."""

    model_config = ConfigDict(extra="forbid")

    db_auth_uri: str = Field(pattern=r"^mongodb://", description="MongoDB URI")
    db_name: str
    json_url: Optional[str] = Field(
        pattern=r"^https?://",
        default=DEFAULT_KEV_URL,
        description="URL to the KEV JSON file",
    )
    schema_url: Optional[str] = Field(
        None,
        pattern=r"^https?://",
        description="URL to the KEV JSON file",
    )


class KEVSyncConfig(BaseModel):
    """Definition of the KEVSync configuration root."""

    model_config = ConfigDict(extra="ignore")

    kevsync: KEVSync
