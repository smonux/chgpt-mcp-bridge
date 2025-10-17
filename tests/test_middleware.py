import asyncio
import ipaddress
import logging
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

    def test_prefers_leftmost_xff_value(self, dummy_call_next):
        networks = [ipaddress.ip_network("198.51.100.0/24")]
        mw = IPAllowlistMiddleware(networks)

        class DummyRequest:
            def __init__(self):
                self.headers = {
                    "x-forwarded-for": "198.51.100.42, 203.0.113.9",
                    "X-Other": "ignored",
                }
                self.client = types.SimpleNamespace(host="203.0.113.10")

        class DummyFastCtx:
            def __init__(self, req):
                self._req = req

            def get_http_request(self):
                return self._req

        request = DummyRequest()
        ctx = types.SimpleNamespace(
            fastmcp_context=DummyFastCtx(request),
            request=None,
            client=None,
            client_address=None,
            state={},
        )

        result = asyncio.run(mw.on_list_tools(ctx, dummy_call_next))
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

    def test_extracts_from_scope_headers_when_headers_fail(self, dummy_call_next):
        networks = [ipaddress.ip_network("198.51.100.0/24")]
        mw = IPAllowlistMiddleware(networks)

        class BadHeaders(dict):
            def get(self, *args, **kwargs):
                raise RuntimeError("boom")

        request = types.SimpleNamespace(
            headers=BadHeaders(),
            scope={"headers": [(b"x-forwarded-for", b"198.51.100.77, 203.0.113.4")]},
            client=None,
        )
        ctx = types.SimpleNamespace(
            fastmcp_context=None,
            request=request,
            client=None,
            client_address=None,
            state={},
        )

        result = asyncio.run(mw.on_call_tool(ctx, dummy_call_next))
        assert result == "OK"

    def test_rejects_when_only_ipv6_present(self, dummy_call_next):
        networks = [ipaddress.ip_network("198.51.100.0/24")]
        mw = IPAllowlistMiddleware(networks)

        request = types.SimpleNamespace(
            headers={"x-forwarded-for": "2001:db8::1"},
            scope={},
            client=None,
        )
        ctx = types.SimpleNamespace(
            fastmcp_context=None,
            request=request,
            client=None,
            client_address=None,
            state={},
        )

        with pytest.raises(PermissionError):
            asyncio.run(mw.on_list_tools(ctx, dummy_call_next))

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

    def test_block_when_token_missing_login(self, fake_ctx, dummy_call_next):
        mw = AllowlistMiddleware()

        class TokenWithoutLogin:
            claims = {}

        with patch("server.get_access_token", return_value=TokenWithoutLogin()):
            with pytest.raises(PermissionError) as ei:
                asyncio.run(mw.on_call_tool(fake_ctx, dummy_call_next))
            assert "anonymous" in str(ei.value).lower()

    def test_block_when_access_token_fetch_fails(self, fake_ctx, dummy_call_next):
        mw = AllowlistMiddleware()

        with patch("server.get_access_token", side_effect=RuntimeError("boom")):
            with pytest.raises(PermissionError) as ei:
                asyncio.run(mw.on_list_tools(fake_ctx, dummy_call_next))
            assert "anonymous" in str(ei.value).lower() or "not allowed" in str(ei.value).lower()

    def test_skip_oauth_env_disables_check(self, fake_ctx, dummy_call_next, monkeypatch):
        monkeypatch.setenv("SKIP_OAUTH", "True")
        mw = AllowlistMiddleware()

        with patch("server.get_access_token") as mock_get:
            result = asyncio.run(mw.on_list_tools(fake_ctx, dummy_call_next))

        assert result == "OK"
        mock_get.assert_not_called()


class TestStartupSecurity:
    def test_requires_at_least_two_measures(self, monkeypatch, caplog):
        import server

        caplog.set_level(logging.INFO)
        monkeypatch.setattr(server, "ALLOWED_NETWORKS", [])
        monkeypatch.setattr(server, "OBFUSCATED_PATH", "shouldberandom")
        monkeypatch.setenv("SKIP_OAUTH", "true")

        with pytest.raises(RuntimeError):
            server._startup_security_check()

        assert any("Refusing to start" in record.message for record in caplog.records)

    def test_reports_active_measures(self, monkeypatch, caplog):
        import server

        caplog.set_level(logging.INFO)
        monkeypatch.setattr(
            server, "ALLOWED_NETWORKS", [ipaddress.ip_network("10.1.0.0/16")]
        )
        monkeypatch.setattr(server, "OBFUSCATED_PATH", "supersecret")
        monkeypatch.delenv("SKIP_OAUTH", raising=False)

        server._startup_security_check()

        messages = [record.message for record in caplog.records]
        assert any("✅ OAuth authentication enabled" in msg for msg in messages)
        assert any("✅ IP allowlist enabled" in msg for msg in messages)
        assert any("✅ Obfuscated URL path enabled" in msg for msg in messages)
