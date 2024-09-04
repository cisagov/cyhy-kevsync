"""The cyhy_kevsync library."""

# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

from ._version import __version__  # noqa: F401
from .main import do_kev_sync

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_SCHEMA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json"

__all__ = [DEFAULT_KEV_URL, DEFAULT_KEV_SCHEMA_URL, "do_kev_sync"]
