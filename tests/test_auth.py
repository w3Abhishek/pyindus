"""Tests for the authentication module."""

import json
import tempfile
from pathlib import Path

import httpx
import pytest
import respx

from pyindus.auth import IndusAuth, INDUS_BASE_URL, LOGIN_BASE_URL
from pyindus.exceptions import AuthenticationError, APIError


# ── Sample response data ─────────────────────────────────────────

SAMPLE_LOGIN_FLOW = {
    "id": "82c94c76-5ee6-4f22-aa32-1c77f0f1f927",
    "ui": {
        "nodes": [
            {
                "attributes": {
                    "name": "csrf_token",
                    "value": "test-csrf-token-value",
                },
            },
            {
                "attributes": {
                    "name": "identifier",
                    "type": "text",
                },
            },
        ],
        "messages": [],
    },
}

SAMPLE_REFRESH_RESPONSE = {
    "success": True,
    "expiresIn": 43200,
    "tokenExpiresAt": 1771660757000,
}

SAMPLE_USER_INFO = {
    "sub": "22e84e9a-92c0-445b-9912-8faeddb8c088",
    "email": "",
    "name": "Test User",
    "tokenExpiresAt": 1771660757000,
    "tokenExpiresIn": 43200,
}


# ── Tests ─────────────────────────────────────────────────────────


class TestLogin:
    @respx.mock
    def test_login_success(self):
        # Mock login flow creation
        respx.post(f"{LOGIN_BASE_URL}/api/flow/login").mock(
            return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW)
        )
        # Mock phone submission (303 = OTP sent)
        respx.post(
            url__startswith=f"{LOGIN_BASE_URL}/identity/self-service/login"
        ).mock(return_value=httpx.Response(303, headers={"location": "/"}))
        # Mock CSRF token refresh
        respx.get(
            url__startswith=f"{LOGIN_BASE_URL}/api/flow/login"
        ).mock(return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW))

        auth = IndusAuth()
        try:
            flow_id = auth.login("+911234567890")
            assert flow_id == "82c94c76-5ee6-4f22-aa32-1c77f0f1f927"
        finally:
            auth.close()

    @respx.mock
    def test_login_flow_creation_fails(self):
        respx.post(f"{LOGIN_BASE_URL}/api/flow/login").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        auth = IndusAuth()
        try:
            with pytest.raises(AuthenticationError, match="Failed to create login flow"):
                auth.login("+911234567890")
        finally:
            auth.close()

    @respx.mock
    def test_login_no_flow_id(self):
        respx.post(f"{LOGIN_BASE_URL}/api/flow/login").mock(
            return_value=httpx.Response(200, json={"ui": {"nodes": []}})
        )

        auth = IndusAuth()
        try:
            with pytest.raises(AuthenticationError, match="No flow ID"):
                auth.login("+911234567890")
        finally:
            auth.close()


class TestVerifyOTP:
    @respx.mock
    def test_verify_otp_success(self):
        # Setup: login first
        respx.post(f"{LOGIN_BASE_URL}/api/flow/login").mock(
            return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW)
        )
        login_route = respx.post(
            url__startswith=f"{LOGIN_BASE_URL}/identity/self-service/login"
        )
        # First call: phone submission (303 = OTP sent)
        # Second call: OTP submission (303 = success)
        login_route.side_effect = [
            httpx.Response(303, headers={"location": f"{LOGIN_BASE_URL}/login?flow=test"}),
            httpx.Response(303, headers={"location": INDUS_BASE_URL}),
        ]
        respx.get(
            url__startswith=f"{LOGIN_BASE_URL}/api/flow/login"
        ).mock(return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW))
        # Mock the redirect follow (use trailing slash for exact match)
        respx.get(f"{INDUS_BASE_URL}/").mock(
            return_value=httpx.Response(200, text="OK")
        )
        # Mock refresh and me
        respx.post(f"{INDUS_BASE_URL}/api/auth/refresh").mock(
            return_value=httpx.Response(200, json=SAMPLE_REFRESH_RESPONSE)
        )
        respx.get(f"{INDUS_BASE_URL}/api/auth/me").mock(
            return_value=httpx.Response(200, json=SAMPLE_USER_INFO)
        )

        auth = IndusAuth()
        try:
            auth.login("+911234567890")
            user = auth.verify_otp("123456")
            assert user.name == "Test User"
            assert auth.is_authenticated is True
        finally:
            auth.close()

    def test_verify_otp_without_login(self):
        auth = IndusAuth()
        try:
            with pytest.raises(AuthenticationError, match="Must call login"):
                auth.verify_otp("123456")
        finally:
            auth.close()

    @respx.mock
    def test_verify_otp_failure(self):
        # Setup: login first
        respx.post(f"{LOGIN_BASE_URL}/api/flow/login").mock(
            return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW)
        )
        login_route = respx.post(
            url__startswith=f"{LOGIN_BASE_URL}/identity/self-service/login"
        )
        login_route.side_effect = [
            httpx.Response(303, headers={"location": "/"}),
            httpx.Response(422, json={
                "ui": {
                    "messages": [{"text": "The code is invalid or has expired"}],
                    "nodes": [],
                },
            }),
        ]
        respx.get(
            url__startswith=f"{LOGIN_BASE_URL}/api/flow/login"
        ).mock(return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW))

        auth = IndusAuth()
        try:
            auth.login("+911234567890")
            with pytest.raises(AuthenticationError, match="OTP verification failed"):
                auth.verify_otp("000000")
        finally:
            auth.close()


class TestRefresh:
    @respx.mock
    def test_refresh_success(self):
        respx.post(f"{INDUS_BASE_URL}/api/auth/refresh").mock(
            return_value=httpx.Response(200, json=SAMPLE_REFRESH_RESPONSE)
        )

        auth = IndusAuth()
        try:
            result = auth.refresh()
            assert result.success is True
            assert result.expires_in == 43200
        finally:
            auth.close()

    @respx.mock
    def test_refresh_expired(self):
        respx.post(f"{INDUS_BASE_URL}/api/auth/refresh").mock(
            return_value=httpx.Response(401, json={"error": "Not authenticated"})
        )

        auth = IndusAuth()
        try:
            with pytest.raises(AuthenticationError, match="Session expired"):
                auth.refresh()
        finally:
            auth.close()


class TestGetMe:
    @respx.mock
    def test_get_me_success(self):
        respx.get(f"{INDUS_BASE_URL}/api/auth/me").mock(
            return_value=httpx.Response(200, json=SAMPLE_USER_INFO)
        )

        auth = IndusAuth()
        try:
            user = auth.get_me()
            assert user.sub == "22e84e9a-92c0-445b-9912-8faeddb8c088"
            assert user.name == "Test User"
        finally:
            auth.close()

    @respx.mock
    def test_get_me_unauthenticated(self):
        respx.get(f"{INDUS_BASE_URL}/api/auth/me").mock(
            return_value=httpx.Response(401, json={"error": "Not authenticated"})
        )

        auth = IndusAuth()
        try:
            with pytest.raises(AuthenticationError, match="Not authenticated"):
                auth.get_me()
        finally:
            auth.close()


class TestSessionPersistence:
    @respx.mock
    def test_save_and_load_session(self):
        respx.post(f"{INDUS_BASE_URL}/api/auth/refresh").mock(
            return_value=httpx.Response(200, json=SAMPLE_REFRESH_RESPONSE)
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            session_path = f.name

        auth = IndusAuth()
        try:
            # Set a cookie manually to simulate authenticated state
            auth.client.cookies.set("test_cookie", "test_value", domain="indus.sarvam.ai")
            auth._authenticated = True
            auth.save_session(session_path)

            # Verify file contents
            data = json.loads(Path(session_path).read_text())
            assert "cookies" in data
            assert data["authenticated"] is True

            # Load in a new auth instance
            auth2 = IndusAuth()
            try:
                result = auth2.load_session(session_path)
                assert result is True
                assert auth2.is_authenticated is True
            finally:
                auth2.close()
        finally:
            auth.close()
            Path(session_path).unlink(missing_ok=True)

    def test_load_nonexistent_session(self):
        auth = IndusAuth()
        try:
            with pytest.raises(AuthenticationError, match="not found"):
                auth.load_session("/nonexistent/path.json")
        finally:
            auth.close()

    @respx.mock
    def test_load_expired_session(self):
        respx.post(f"{INDUS_BASE_URL}/api/auth/refresh").mock(
            return_value=httpx.Response(401, json={"error": "Not authenticated"})
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"cookies": [], "authenticated": True}, f)
            session_path = f.name

        auth = IndusAuth()
        try:
            result = auth.load_session(session_path)
            assert result is False
            assert auth.is_authenticated is False
        finally:
            auth.close()
            Path(session_path).unlink(missing_ok=True)


class TestCSRFExtraction:
    def test_extract_from_ui_nodes(self):
        flow_data = {
            "ui": {
                "nodes": [
                    {
                        "attributes": {
                            "name": "csrf_token",
                            "value": "my-csrf-token",
                        },
                    },
                ],
            },
        }
        token = IndusAuth._extract_csrf_token(flow_data)
        assert token == "my-csrf-token"

    def test_extract_from_top_level(self):
        flow_data = {"csrf_token": "top-level-token"}
        token = IndusAuth._extract_csrf_token(flow_data)
        assert token == "top-level-token"

    def test_no_token_found(self):
        flow_data = {"ui": {"nodes": []}}
        token = IndusAuth._extract_csrf_token(flow_data)
        assert token is None


class TestErrorExtraction:
    def test_extract_from_ui_messages(self):
        body = {
            "ui": {
                "messages": [{"text": "Invalid code"}],
                "nodes": [],
            },
        }
        msg = IndusAuth._extract_error_message(body)
        assert msg == "Invalid code"

    def test_extract_from_node_messages(self):
        body = {
            "ui": {
                "messages": [],
                "nodes": [
                    {"messages": [{"text": "Field error"}]},
                ],
            },
        }
        msg = IndusAuth._extract_error_message(body)
        assert msg == "Field error"

    def test_extract_from_error_dict(self):
        body = {
            "ui": {"messages": [], "nodes": []},
            "error": {"message": "Something broke"},
        }
        msg = IndusAuth._extract_error_message(body)
        assert msg == "Something broke"
