"""The cyhy_kevsync library."""

# We disable the following Flake8 checks:
# - "Module level import not at top of file (E402)" here because the constants
#   need to be defined early to prevent a circular import issue.
# - "Module imported but unused (F401)" here because although this import is not
#   directly used, it populates the value package_name.__version__, which is
#   used to get version information about this Python package.

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_SCHEMA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json"

from ._version import __version__  # noqa: F401, E402
from .main import do_kev_sync  # noqa: E402

__all__ = ["do_kev_sync", DEFAULT_KEV_SCHEMA_URL, DEFAULT_KEV_URL]
