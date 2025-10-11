import os, asyncio, json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # load .env automatically

from fastmcp import FastMCP
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.middleware import Middleware, MiddlewareContext, CallNext
from fastmcp.server.dependencies import get_access_token
from typing import Any

# === Environment variables ===
GITHUB_USERS = {u.strip() for u in os.getenv("GITHUB_USERS", "").split(",") if u.strip()}
EXTERNAL_HOSTNAME = os.getenv("EXTERNAL_HOSTNAME")  # e.g. "<server.tailnet>.ts.net"
INTERNAL_PORT = int(os.getenv("INTERNAL_PORT", "8888"))
INTERNAL_HOST = os.getenv("INTERNAL_HOST", "127.0.0.1")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

MCP_JSON_PATH = os.getenv("MCP_JSON_PATH", "./mcp.json")
BASE_URL_SCHEME = os.getenv("BASE_URL_SCHEME", "https")
OAUTH_REDIRECT_PATH = os.getenv("OAUTH_REDIRECT_PATH", "/auth/callback")
SERVER_NAME = os.getenv("SERVER_NAME", "fastmcp-proxy")

if not (GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET and EXTERNAL_HOSTNAME):
    raise RuntimeError("Missing required env vars: GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, EXTERNAL_HOSTNAME")

BASE_URL = f"{BASE_URL_SCHEME}://{EXTERNAL_HOSTNAME}".rstrip("/")

# === Auth provider (GitHub OAuth) ===
auth_provider = GitHubProvider(
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    base_url=BASE_URL,
    redirect_path=OAUTH_REDIRECT_PATH,
)

# === Allowlist middleware ===
class AllowlistMiddleware(Middleware):
    def _check(self) -> None:
        token = get_access_token()
        login = token.claims.get("login") if token else None
        if not login or (GITHUB_USERS and login not in GITHUB_USERS):
            raise PermissionError(f"User '{login or 'anonymous'}' is not allowed")

    async def on_list_tools(self, ctx: MiddlewareContext, call_next: CallNext) -> Any:
        self._check()
        return await call_next(ctx)

    async def on_call_tool(self, ctx: MiddlewareContext, call_next: CallNext) -> Any:
        self._check()
        return await call_next(ctx)

if __name__ == "__main__":
    config = json.loads(Path(MCP_JSON_PATH).read_text(encoding="utf-8"))
    proxy = FastMCP.as_proxy(config, name=SERVER_NAME, auth=auth_provider)
    proxy.add_middleware(AllowlistMiddleware())
    proxy.run(transport="http", host=INTERNAL_HOST, port=INTERNAL_PORT)

