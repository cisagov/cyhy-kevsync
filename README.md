# cyhy-kevsync #

[![GitHub Build Status](https://github.com/cisagov/cyhy-kevsync/workflows/build/badge.svg)](https://github.com/cisagov/cyhy-kevsync/actions)
[![CodeQL](https://github.com/cisagov/cyhy-kevsync/workflows/CodeQL/badge.svg)](https://github.com/cisagov/cyhy-kevsync/actions/workflows/codeql-analysis.yml)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/cyhy-kevsync/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/cyhy-kevsync?branch=develop)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/cyhy-kevsync/develop/badge.svg)](https://snyk.io/test/github/cisagov/cyhy-kevsync)

`cyhy-kevsync` is Python library that can retrieve a JSON file containing Known
Exploited Vulnerabilities (such as the [JSON
file](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json)
for the [CISA Known Exploited Vulnerabilities
Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) and
import the data into a MongoDB collection.

## Pre-requisites ##

- [Python 3.12](https://www.python.org/downloads/) or newer
- A running [MongoDB](https://www.mongodb.com/) instance that you have access to

## Starting a Local MongoDB Instance for Testing ##

> [!IMPORTANT]
> This requires [Docker](https://www.docker.com/) to be installed in
> order for this to work.

You can start a local MongoDB instance in a container with the following
command:

```console
pytest -vs --mongo-express
```

> [!NOTE]
> The command `pytest -vs --mongo-express` not only starts a local
> MongoDB instance, but also runs all the `cyhy-kevsync` unit tests, which will
> create various collections and documents in the database.

Sample output (trimmed to highlight the important parts):

```console
<snip>
MongoDB is accessible at mongodb://mongoadmin:secret@localhost:32784 with database named "test"
Mongo Express is accessible at http://admin:pass@localhost:8081

Press Enter to stop Mongo Express and MongoDB containers...
```

Based on the example output above, you can access the MongoDB instance at
`mongodb://mongoadmin:secret@localhost:32784` and the Mongo Express web
interface at `http://admin:pass@localhost:8081`.  Note that the MongoDB
containers will remain running until you press "Enter" in that terminal.

## Example Usage ##

Once you have a MongoDB instance running, the sample Python code below
demonstrates how to initialize the CyHy database, fetch KEV data from a source,
validate it, and then load the data into to your database.

```python
import asyncio
from cyhy_db import initialize_db
from cyhy_db.models import KEVDoc
from cyhy_kevsync import DEFAULT_KEV_SCHEMA_URL, DEFAULT_KEV_URL
from cyhy_kevsync.kev_sync import fetch_kev_data, sync_kev_docs, validate_kev_data

async def main():
    # Initialize the CyHy database
    await initialize_db("mongodb://mongoadmin:secret@localhost:32784", "test")

    # Count number of KEV documents in DB before sync
    kev_count_before = await KEVDoc.find_all().count()
    print(f"KEV documents in DB before sync: {kev_count_before}")

    # Fetch KEV data from the default source
    kev_data = await fetch_kev_data(DEFAULT_KEV_URL)

    # Validate the KEV data against the default schema
    await validate_kev_data(kev_data, DEFAULT_KEV_SCHEMA_URL)

    # Sync the KEV data to the database
    await sync_kev_docs(kev_data)

    # Count number of KEV documents in DB after sync
    kev_count_after = await KEVDoc.find_all().count()
    print(f"KEV documents in DB after sync: {kev_count_after}")

asyncio.run(main())
```

Output:

```console
KEV documents in DB before sync: 0
Processing KEV feed ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:01
Deleting KEV docs ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KEV documents in DB after sync: 1193
```

### Environment Variables ###

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGO_INITDB_ROOT_USERNAME` | The MongoDB root username | `mongoadmin` |
| `MONGO_INITDB_ROOT_PASSWORD` | The MongoDB root password | `secret` |
| `DATABASE_NAME` | The name of the database to use for testing | `test` |
| `MONGO_EXPRESS_PORT` | The port to use for the Mongo Express web interface | `8081` |

### Pytest Options ###

| Option | Description | Default |
|--------|-------------|---------|
| `--mongo-express` | Start a local MongoDB instance and Mongo Express web interface | n/a |
| `--mongo-image-tag` | The tag of the MongoDB Docker image to use | `docker.io/mongo:latest` |
| `--runslow` | Run slow tests | n/a |

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
