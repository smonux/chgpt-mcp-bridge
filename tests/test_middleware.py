import asyncio
import ipaddress
import os
import types
import pytest
from unittest.mock import patch

from server import IPAllowlistMiddleware, AllowlistMiddleware


@pytest.fixture
def dummy_call_next():
    async def _call_next(ctx):
        return "OK"
    return _call_next


@pytest.fixture
def fake_ctx():
    return types.SimpleNamespace(
        fastmcp_context=None,
        request=None,
        client=None,
        client_address=None,
        state={},
    )


class TestIPAllowlistMiddleware:
    def test_allow_when_ip_in_range(self, fake_ctx, dummy_call_next):
        networks = [ipaddress.ip_network("10.0.0.0/8")]
        mw = IPAllowlistMiddleware(networks)
        with patch.object(mw, "_extract_client_ipv4", return_value="10.1.2.3"):
            result = asyncio.run(mw.on_list_tools(fake_ctx, dummy_call_next))
            assert result == "OK"

    def test_block_when_ip_out_of_range(self, fake_ctx, dummy_call_next):
        networks = [ipaddress.ip_network("10.0.0.0/8")]
        mw = IPAllowlistMiddleware(networks)
        with patch.object(mw, "_extract_client_ipv4", return_value="192.168.1.2"):
            with pytest.raises(PermissionError) as ei:
                asyncio.run(mw.on_list_tools(fake_ctx, dummy_call_next))
            assert "not allowed" in str(ei.value).lower()

    def test_block_when_ip_missing_or_invalid(self, fake_ctx, dummy_call_next):
        networks = [ipaddress.ip_network("10.0.0.0/8")]
        mw = IPAllowlistMiddleware(networks)
        with patch.object(mw, "_extract_client_ipv4", return_value=None):
            with pytest.raises(PermissionError) as ei:
                asyncio.run(mw.on_list_tools(fake_ctx, dummy_call_next))
            msg = str(ei.value).lower()
            assert "invalid xff" in msg or "not allowed" in msg

    def test_allow_when_no_allowlist_configured(self, fake_ctx, dummy_call_next):
        networks = []
        mw = IPAllowlistMiddleware(networks)
        with patch.object(mw, "_extract_client_ipv4", return_value="203.0.113.1"):
            result = asyncio.run(mw.on_call_tool(fake_ctx, dummy_call_next))
            assert result == "OK"


class TestAllowlistMiddleware:
    @pytest.fixture(autouse=True)
    def clear_env(self, monkeypatch):
        monkeypatch.delenv("GITHUB_USERS", raising=False)

    def test_block_when_not_authenticated(self, fake_ctx, dummy_call_next, monkeypatch):
        mw = AllowlistMiddleware()
        # simulate no token/login; AllowlistMiddleware uses get_access_token() internally
        with patch("server.get_access_token", return_value=None):
            with pytest.raises(PermissionError) as ei:
                asyncio.run(mw.on_list_tools(fake_ctx, dummy_call_next))
            assert "anonymous" in str(ei.value).lower() or "not allowed" in str(ei.value).lower()

    def test_block_when_user_not_in_allowlist(self, fake_ctx, dummy_call_next, monkeypatch):
        monkeypatch.setenv("GITHUB_USERS", "alice,bob")
        # Re-import AllowlistMiddleware with updated env variable
        from importlib import reload
        import server as server_mod
        reload(server_mod)
        mw = server_mod.AllowlistMiddleware()

        class Token:
            claims = {"login": "charlie"}
        with patch("server.get_access_token", return_value=Token()):
            with pytest.raises(PermissionError) as ei:
                asyncio.run(mw.on_call_tool(fake_ctx, dummy_call_next))
            assert "user 'charlie' is not allowed".lower() in str(ei.value).lower()

    def test_allow_when_user_in_allowlist(self, fake_ctx, dummy_call_next, monkeypatch):
        monkeypatch.setenv("GITHUB_USERS", "alice,bob")
        from importlib import reload
        import server as server_mod
        reload(server_mod)
        mw = server_mod.AllowlistMiddleware()

        class Token:
            claims = {"login": "alice"}
        with patch("server.get_access_token", return_value=Token()):
            result = asyncio.run(mw.on_list_tools(fake_ctx, dummy_call_next))
            assert result == "OK"

    def test_allow_when_no_user_allowlist(self, fake_ctx, dummy_call_next, monkeypatch):
        # No GITHUB_USERS => any authenticated user allowed
        # Ensure the module-level set is empty even if prior tests reloaded the module
        with patch("server.GITHUB_USERS", set()):
            mw = AllowlistMiddleware()
            class Token:
                claims = {"login": "dora"}
            with patch("server.get_access_token", return_value=Token()):
                result = asyncio.run(mw.on_call_tool(fake_ctx, dummy_call_next))
                assert result == "OK"
