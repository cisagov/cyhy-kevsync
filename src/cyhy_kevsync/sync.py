import time
import random
from rich.progress import track
from . import DEFAULT_KEV_URL


def sync(url: str = DEFAULT_KEV_URL) -> None:
    """Synchronize the KEV data from the given URL."""

    for _ in track(
        range(100),
        description="KEV Syncing",
    ):
        time.sleep(random.uniform(0.01, 1))
