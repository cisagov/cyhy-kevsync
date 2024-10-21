"""pytest plugin configuration.

https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins
"""

# Standard Python Libraries
import asyncio
import logging
import os
import time

# Third-Party Libraries
from cyhy_db import initialize_db
import docker
from motor.core import AgnosticClient
import pytest
from rich.logging import RichHandler

MONGO_INITDB_ROOT_USERNAME = os.environ.get("MONGO_INITDB_ROOT_USERNAME", "mongoadmin")
MONGO_INITDB_ROOT_PASSWORD = os.environ.get("MONGO_INITDB_ROOT_PASSWORD", "secret")
DATABASE_NAME = os.environ.get("DATABASE_NAME", "test")
MONGO_EXPRESS_PORT = os.environ.get("MONGO_EXPRESS_PORT", 8081)

# Set the default event loop policy to be compatible with asyncio
AgnosticClient.get_io_loop = asyncio.get_running_loop


@pytest.fixture(autouse=True)
def group_github_log_lines(request):
    """Group log lines when running in GitHub actions."""
    # Group output from each test with workflow log groups
    # https://help.github.com/en/actions/reference/workflow-commands-for-github-actions#grouping-log-lines

    if os.environ.get("GITHUB_ACTIONS") != "true":
        # Not running in GitHub actions
        yield
        return
    # Group using the current test name
    print()
    print(f"::group::{request.node.name}")
    yield
    print()
    print("::endgroup::")


@pytest.fixture(scope="session")
def docker_client():
    """Fixture for the Docker client."""
    yield docker.from_env()


@pytest.fixture(scope="session")
def mongodb_container(docker_client, mongo_image_tag):
    """Fixture for the MongoDB test container."""
    container = docker_client.containers.run(
        mongo_image_tag,
        detach=True,
        environment={
            "MONGO_INITDB_ROOT_USERNAME": MONGO_INITDB_ROOT_USERNAME,
            "MONGO_INITDB_ROOT_PASSWORD": MONGO_INITDB_ROOT_PASSWORD,
        },
        name="mongodb",
        ports={"27017/tcp": None},
        volumes={},
        healthcheck={
            "test": ["CMD", "mongosh", "--eval", "'db.runCommand(\"ping\").ok'"],
            "interval": 1000000000,  # ns -> 1 second
            "timeout": 1000000000,  # ns -> 1 second
            "retries": 5,
            "start_period": 3000000000,  # ns -> 3 seconds
        },
    )
    TIMEOUT = 180
    # Wait for container to be healthy
    for _ in range(TIMEOUT):
        # Verify the container is still running
        container.reload()
        assert container.status == "running", "The container unexpectedly exited."
        status = container.attrs["State"]["Health"]["Status"]
        if status == "healthy":
            break
        time.sleep(1)
    else:
        assert (
            False
        ), f"Container status did not transition to 'healthy' within {TIMEOUT} seconds."

    yield container
    container.stop()
    container.remove(force=True)


@pytest.fixture(autouse=True, scope="session")
def mongo_express_container(docker_client, db_uri, request):
    """Fixture for the Mongo Express test container."""
    if not request.config.getoption("--mongo-express"):
        yield None
        return

    # Configuration for Mongo Express
    mongo_express_container = docker_client.containers.run(
        "mongo-express",
        environment={
            "ME_CONFIG_MONGODB_ADMINUSERNAME": MONGO_INITDB_ROOT_USERNAME,
            "ME_CONFIG_MONGODB_ADMINPASSWORD": MONGO_INITDB_ROOT_PASSWORD,
            "ME_CONFIG_MONGODB_SERVER": "mongodb",
            "ME_CONFIG_MONGODB_ENABLE_ADMIN": "true",
        },
        links={"mongodb": "mongodb"},
        ports={"8081/tcp": 8081},
        detach=True,
    )

    def fin():
        if request.config.getoption("--mongo-express"):
            print(
                f'\n\nMongoDB is accessible at {db_uri} with database named "{DATABASE_NAME}"'
            )
            print(
                f"Mongo Express is accessible at http://admin:pass@localhost:{MONGO_EXPRESS_PORT}\n"
            )
            input("Press Enter to stop Mongo Express and MongoDB containers...")
        mongo_express_container.stop()
        mongo_express_container.remove(force=True)

    request.addfinalizer(fin)
    yield mongo_express_container


@pytest.fixture(scope="session")
def db_uri(mongodb_container):
    """Fixture for the database URI."""
    mongo_port = mongodb_container.attrs["NetworkSettings"]["Ports"]["27017/tcp"][0][
        "HostPort"
    ]
    uri = f"mongodb://{MONGO_INITDB_ROOT_USERNAME}:{MONGO_INITDB_ROOT_PASSWORD}@localhost:{mongo_port}"
    yield uri


@pytest.fixture(scope="session")
def db_name(mongodb_container):
    """Fixture for the database name."""
    yield DATABASE_NAME


@pytest.fixture(autouse=True, scope="session")
async def db_client(db_uri):
    """Fixture for client init."""
    print(f"Connecting to {db_uri}")
    await initialize_db(db_uri, DATABASE_NAME)


def pytest_addoption(parser):
    """Add new commandline options to pytest."""
    parser.addoption(
        "--runslow", action="store_true", default=False, help="run slow tests"
    )
    parser.addoption(
        "--mongo-image-tag",
        action="store",
        default="docker.io/mongo:latest",
        help="mongodb image tag to use for testing",
    )
    parser.addoption(
        "--mongo-express",
        action="store_true",
        default=False,
        help="run Mongo Express for database inspection",
    )


@pytest.fixture(scope="session")
def mongo_image_tag(request):
    """Get the image tag to test."""
    return request.config.getoption("--mongo-image-tag")


def pytest_configure(config):
    """Register new markers."""
    config.addinivalue_line("markers", "slow: mark test as slow")

    # Set logging level to debug for your specific logger
    logger = logging.getLogger("cyhy_kevsync")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(RichHandler(rich_tracebacks=True, show_path=True))


def pytest_collection_modifyitems(config, items):
    """Modify collected tests based on custom marks and commandline options."""
    if config.getoption("--runslow"):
        # --runslow given in cli: do not skip slow tests
        return
    skip_slow = pytest.mark.skip(reason="need --runslow option to run")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)
