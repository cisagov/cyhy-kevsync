"""
This is the setup module for the example project.

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
- https://blog.ionelmc.ro/2014/05/25/python-packaging/#the-structure
"""

# Standard Python Libraries
import codecs
from glob import glob
from os.path import abspath, basename, dirname, join, splitext

# Third-Party Libraries
from setuptools import find_packages, setup


def readme():
    """Read in and return the contents of the project's README.md file."""
    with open("README.md", encoding="utf-8") as f:
        return f.read()


# Below two methods were pulled from:
# https://packaging.python.org/guides/single-sourcing-package-version/
def read(rel_path):
    """Open a file for reading from a given relative path."""
    here = abspath(dirname(__file__))
    with codecs.open(join(here, rel_path), "r") as fp:
        return fp.read()


def get_version(version_file):
    """Extract a version number from the given file path."""
    for line in read(version_file).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")


setup(
    name="cyhy-kevsync",
    # Versions should comply with PEP440
    version=get_version("src/cyhy_kevsync/_version.py"),
    description="Cyber Hygiene known exploited vulnerability (KEV) synchronization tool",
    long_description=readme(),
    long_description_content_type="text/markdown",
    # Landing page for CISA's Known Exploited Vulnerabilities Catalog
    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    # Additional URLs for this project per
    # https://packaging.python.org/guides/distributing-packages-using-setuptools/#project-urls
    project_urls={
        "Source": "https://github.com/cisagov/cyhy-kevsync",
        "Tracker": "https://github.com/cisagov/cyhy-kevsync/issues",
    },
    # Author details
    author="Mark Feldhousen",
    author_email="mark.feldhousen@cisa.dhs.gov",
    license="License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 5 - Production/Stable",
        # Indicate who your project is intended for
        "Intended Audience :: Developers",
        # Pick your license as you wish (should match "license" above)
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    python_requires=">=3.12",
    # What does your project relate to?
    keywords="cyhy kev sync",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={"cyhy_kevsync": ["py.typed"]},
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    install_requires=[
        "cyhy-config @ git+https://github.com/cisagov/cyhy-config.git@v1",
        "cyhy-db @ git+https://github.com/cisagov/cyhy-db.git@v1",
        "cyhy-logging @ git+https://github.com/cisagov/cyhy-logging.git@v1",
        "jsonschema",
        "rich",
        "setuptools",
    ],
    extras_require={
        "test": [
            "coverage",
            "coveralls",
            "docker",
            "pre-commit",
            "pytest-asyncio",
            "pytest-cov",
            "pytest",
        ]
    },
    # Conveniently allows one to run the CLI tool as `cyhy-kevsync`
    entry_points={"console_scripts": ["cyhy-kevsync = cyhy_kevsync.main:main"]},
)
