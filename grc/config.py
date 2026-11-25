"""Configuration read from environment variables.

The application reads exactly one setting from the environment: the path to
its SQLite database file. No credentials, tokens, or third party endpoints
are configured here because the application makes no external network calls
and talks to no external service. See .env.example for the variable name.
"""

import os

DEFAULT_DB_PATH = "secure-grc.db"


def database_path():
    """Return the configured database path, falling back to a local default."""
    return os.environ.get("SECURE_GRC_DB_PATH", DEFAULT_DB_PATH)
