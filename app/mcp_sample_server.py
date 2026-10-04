"""Sample-data mode for the Falcon MCP page: the official falcon-mcp server (same tools, schemas, FQL guides), with its
Falcon API client replaced by one that answers from the sample database (app.sample_api). Nothing leaves the machine;
operations that would change something in a tenant are refused.

Run by app.falconmcp in sample mode:  python -m app.mcp_sample_server -t streamable-http --port N --api-key K [--read-only]"""
import sys

from falcon_mcp import client as fclient
from falcon_mcp import server as fserver

from . import sample_api


class SampleClient(fclient.FalconClient):
    """Answers falcon-mcp's API calls from the sample database."""

    def authenticate(self) -> bool:  # noqa: D401
        return True

    def is_authenticated(self) -> bool:
        return True

    def _ensure_token_fresh(self) -> None:
        return None

    def command(self, operation: str, **kw):
        return sample_api.command(operation, **kw)


def main():
    fserver.FalconClient = SampleClient  # the real server, answering from the sample database
    sys.argv[0] = "falcon-mcp"
    fserver.main()


if __name__ == "__main__":
    main()
