"""Configuration: read DATA_SOURCE and GRAPH_TOKEN from the environment or a .env file.

The token is never hard-coded. It only ever comes from the environment.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Project root = the folder that holds README.md and data/.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MOCK_DIR = PROJECT_ROOT / "data" / "mock"
OUTPUT_DIR = PROJECT_ROOT / "output"

# Load .env if it exists. Real environment variables win over .env values.
load_dotenv(PROJECT_ROOT / ".env", override=False)

VALID_SOURCES = ("mock", "graph")


def get_data_source() -> str:
    """Return "mock" or "graph". Defaults to "mock" for anything unexpected."""
    value = os.getenv("DATA_SOURCE", "mock").strip().lower()
    return value if value in VALID_SOURCES else "mock"


def get_graph_token() -> str | None:
    """Return the Graph access token, or None if it isn't set."""
    token = os.getenv("GRAPH_TOKEN", "").strip()
    return token or None
