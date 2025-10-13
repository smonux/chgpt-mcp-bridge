import os, asyncio, json
from pathlib import Path
from dotenv import load_dotenv
import ipaddress
from typing import Any, Iterable, List, Optional

load_dotenv()  # load .env automatically

from fastmcp import FastMCP
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.middleware import Middleware, MiddlewareContext, CallNext
from fastmcp.server.dependencies import get_access_token

# === Environment variables
ALLOWED_RANGES_FILE = os.getenv('ALLOWED_RANGES_FILE', '')
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
OBFUSCATED_PATH= os.getenv("OBFUSCATED_PATH", "shouldberandom")

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

# === Helper: load IPv4 CIDRs from file (newline separated) ===
def load_ipv4_cidrs_from_file(path: str) -> List[ipaddress.IPv4Network]:
    networks: List[ipaddress.IPv4Network] = []
    if not path:
        return networks
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Allowed ranges file not found: {path}")
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            # Force IPv4 network parsing; accept single-host entries
            net = ipaddress.IPv4Network(line, strict=False)
            networks.append(net)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 CIDR/network in {path}: '{line}' -> {exc}")
    return networks

ALLOWED_NETWORKS: List[ipaddress.IPv4Network] = []
if ALLOWED_RANGES_FILE:
    ALLOWED_NETWORKS = load_ipv4_cidrs_from_file(ALLOWED_RANGES_FILE)

# === IP allowlist middleware (IPv4-only, X-Forwarded-For strict) ===
class IPAllowlistMiddleware(Middleware):
    def __init__(self, allowed_networks: Iterable[ipaddress.IPv4Network]):
        super().__init__()
        self.allowed_networks = list(allowed_networks)

    def _is_allowed_ip(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return False
        for net in self.allowed_networks:
            if ip_obj in net:
                return True
        return False

    def _extract_client_ipv4(self, ctx: MiddlewareContext) -> Optional[str]:
        """Extract client IPv4 using the same approach as gpt-mcp-filter's MCP manager:
        - Prefer FastMCP context HTTP request (fctx.get_http_request())
          * default to TCP peer (req.client.host)
          * if X-Forwarded-For present, take the left-most value
        - Validate strictly as IPv4.
        - Fall back to earlier generic extraction if FastMCP context is missing.
        """
        # 1) Try FastMCP context request (most reliable in this stack)
        try:
            fctx = getattr(ctx, 'fastmcp_context', None)
            if fctx is not None:
                req = fctx.get_http_request()
                remote_ip = getattr(getattr(req, 'client', None), 'host', None)
                # Override with X-Forwarded-For first value if present
                try:
                    for k, v in req.headers.items():
                        if k.lower() == 'x-forwarded-for':
                            remote_ip = v.split(',')[0].strip()
                            break
                except Exception:
                    pass
                if remote_ip:
                    try:
                        ipaddress.IPv4Address(remote_ip)
                        return remote_ip
                    except ValueError:
                        return None
        except Exception:
            pass

        # 2) Fallback: Attempt to read request headers in common ASGI shapes
        req = getattr(ctx, 'request', None)
        xff = None
        if req is not None:
            try:
                xff = req.headers.get('x-forwarded-for')
            except Exception:
                scope = getattr(req, 'scope', None)
                if scope and 'headers' in scope:
                    for k, v in scope['headers']:
                        try:
                            if k.decode().lower() == 'x-forwarded-for':
                                xff = v.decode()
                                break
                        except Exception:
                            continue
        if xff:
            first = xff.split(',')[0].strip()
            try:
                ipaddress.IPv4Address(first)
                return first
            except ValueError:
                return None

        try:
            if req is not None:
                client = getattr(req, 'client', None)
                if client:
                    candidate = client[0] if isinstance(client, tuple) and len(client) >= 1 else getattr(client, 'host', None)
                    if candidate is not None:
                        ipaddress.IPv4Address(candidate)
                        return candidate
        except Exception:
            pass

        try:
            client = getattr(ctx, 'client', None) or getattr(ctx, 'client_address', None)
            if client:
                candidate = client[0] if isinstance(client, tuple) and len(client) >= 1 else getattr(client, 'host', None)
                if candidate is not None:
                    ipaddress.IPv4Address(candidate)
                    return candidate
        except Exception:
            pass

        return None

    async def on_list_tools(self, ctx: MiddlewareContext, call_next: CallNext) -> Any:
        # If no networks configured, allow by default
        if not self.allowed_networks:
            return await call_next(ctx)

        client_ip = self._extract_client_ipv4(ctx)
        if not client_ip:
            # Treat missing/invalid XFF or invalid peer as not allowed
            raise PermissionError(f"IP '{client_ip or 'unknown'}' not allowed or invalid XFF")

        if not self._is_allowed_ip(client_ip):
            raise PermissionError(f"IP '{client_ip}' not allowed")

        return await call_next(ctx)

    async def on_call_tool(self, ctx: MiddlewareContext, call_next: CallNext) -> Any:
        # same logic for call_tool
        if not self.allowed_networks:
            return await call_next(ctx)

        client_ip = self._extract_client_ipv4(ctx)
        if not client_ip:
            raise PermissionError(f"IP '{client_ip or 'unknown'}' not allowed or invalid XFF")

        if not self._is_allowed_ip(client_ip):
            raise PermissionError(f"IP '{client_ip}' not allowed")

        return await call_next(ctx)

# === Allowlist middleware (GitHub users) ===
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

    # Add IP allowlist middleware first (so it runs before GitHub checks)
    if ALLOWED_NETWORKS:
        proxy.add_middleware(IPAllowlistMiddleware(ALLOWED_NETWORKS))

    # Keep the GitHub allowlist middleware
    proxy.add_middleware(AllowlistMiddleware())

    proxy.run(transport="http", host=INTERNAL_HOST, port=INTERNAL_PORT, path=f"/{OBFUSCATED_PATH}")

