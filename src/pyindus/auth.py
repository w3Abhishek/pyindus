"""Authentication module for Indus API.

Handles the Ory/Kratos-based login flow:
1. Initiate login flow → get flow ID and CSRF token
2. Submit phone number → triggers OTP via SMS
3. Submit OTP code → completes login, receives session cookies
4. Refresh Indus auth token using session cookies
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

from pyindus.exceptions import AuthenticationError, APIError
from pyindus.models import UserInfo, RefreshResponse

logger = logging.getLogger(__name__)

INDUS_BASE_URL = "https://indus.sarvam.ai"
LOGIN_BASE_URL = "https://login.sarvam.ai"


class IndusAuth:
    """Handles authentication with the Indus platform.

    The Indus platform uses Ory/Kratos for identity management with
    phone number + OTP authentication. Session state is maintained
    via cookies.
    """

    def __init__(self, http_client: httpx.Client | None = None):
        self._client = http_client or httpx.Client(
            follow_redirects=False,
            timeout=30.0,
            headers={
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/144.0.0.0 Safari/537.36"
                ),
                "accept": "*/*",
                "accept-language": "en-US,en;q=0.9",
            },
        )
        self._owns_client = http_client is None
        self._flow_id: str | None = None
        self._csrf_token: str | None = None
        self._phone: str | None = None
        self._authenticated = False

    @property
    def client(self) -> httpx.Client:
        """The underlying HTTP client (shares cookies across auth and chat)."""
        return self._client

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    def login(self, phone: str) -> str:
        """Initiate login flow with phone number.

        Args:
            phone: Phone number with country code (e.g., "+918874163264")

        Returns:
            Flow ID for the login flow.

        Raises:
            AuthenticationError: If the login flow fails.
        """
        self._phone = phone

        # Step 1: Create a new login flow
        logger.info("Creating login flow...")
        resp = self._client.post(
            f"{LOGIN_BASE_URL}/api/flow/login",
            json={"returnTo": INDUS_BASE_URL},
        )
        if resp.status_code != 200:
            raise AuthenticationError(
                f"Failed to create login flow: {resp.status_code} {resp.text}"
            )
        flow_data = resp.json()
        self._flow_id = flow_data.get("id")
        if not self._flow_id:
            raise AuthenticationError(
                f"No flow ID in login response: {flow_data}"
            )

        # Now fetch the actual flow data to get the CSRF token
        self._refresh_csrf_token()
        if not self._csrf_token:
            raise AuthenticationError("Could not extract CSRF token from flow.")
        
        logger.info("Login flow created: %s", self._flow_id)

        # Step 2: Submit phone number to trigger OTP
        logger.info("Submitting phone number to trigger OTP...")
        form_data = {
            "csrf_token": self._csrf_token,
            "method": "code",
            "identifier": phone,
        }
        resp = self._client.post(
            f"{LOGIN_BASE_URL}/identity/self-service/login",
            params={"flow": self._flow_id},
            content=urlencode(form_data),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

        # Expect a 303 redirect (OTP sent) or 422 (validation error) or 200
        if resp.status_code == 303:
            location = resp.headers.get("location", "")
            if "error" in location:
                raise AuthenticationError(f"Login failed: Redirected to error page ({location})")
            logger.info("OTP sent successfully. Waiting for code...")
        elif resp.status_code in (200, 422):
            # Check if there's an error in the response
            try:
                body = resp.json()
                if "error" in body:
                    raise AuthenticationError(
                        f"Login error: {body['error']}"
                    )
            except (json.JSONDecodeError, KeyError):
                pass
            logger.info("OTP sent (status %d). Waiting for code...", resp.status_code)
        else:
            raise AuthenticationError(
                f"Failed to submit phone: {resp.status_code} {resp.text}"
            )

        # Step 3: Refresh CSRF token from updated flow
        self._refresh_csrf_token()

        return self._flow_id

    def verify_otp(self, code: str) -> UserInfo:
        """Submit OTP code to complete login.

        Args:
            code: The OTP code received via SMS.

        Returns:
            UserInfo for the authenticated user.

        Raises:
            AuthenticationError: If OTP verification fails.
        """
        if not self._flow_id or not self._csrf_token or not self._phone:
            raise AuthenticationError(
                "Must call login() before verify_otp()"
            )

        logger.info("Submitting OTP code...")
        form_data = {
            "csrf_token": self._csrf_token,
            "method": "code",
            "identifier": self._phone,
            "code": code,
        }
        resp = self._client.post(
            f"{LOGIN_BASE_URL}/identity/self-service/login",
            params={"flow": self._flow_id},
            content=urlencode(form_data),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

        if resp.status_code == 303:
            # Follow the redirect to indus.sarvam.ai to set cookies
            location = resp.headers.get("location", "")
            if "error" in location:
                raise AuthenticationError(f"OTP verification failed: Redirected to error page ({location})")
            logger.info("Login successful, following redirect to: %s", location)
            if location:
                # Follow redirect — this sets the session cookies on indus.sarvam.ai
                self._client.get(location)
        elif resp.status_code == 200:
            # Might have the session inline
            try:
                body = resp.json()
                if "error" in body:
                    raise AuthenticationError(
                        f"OTP verification failed: {body['error']}"
                    )
            except (json.JSONDecodeError, KeyError):
                pass
        elif resp.status_code == 422:
            try:
                body = resp.json()
                error_msg = self._extract_error_message(body)
                raise AuthenticationError(
                    f"OTP verification failed: {error_msg}"
                )
            except (json.JSONDecodeError, KeyError):
                raise AuthenticationError(
                    f"OTP verification failed: {resp.status_code} {resp.text}"
                )
        else:
            raise AuthenticationError(
                f"OTP verification failed: {resp.status_code} {resp.text}"
            )

        # Step 4: Refresh the Indus auth token
        self.refresh()

        # Step 5: Get user info
        user_info = self.get_me()
        self._authenticated = True
        logger.info("Authenticated as: %s", user_info.name)
        return user_info

    def refresh(self) -> RefreshResponse:
        """Refresh the Indus auth token.

        Returns:
            RefreshResponse with token expiry info.

        Raises:
            AuthenticationError: If token refresh fails.
        """
        logger.debug("Refreshing auth token...")
        resp = self._client.post(
            f"{INDUS_BASE_URL}/api/auth/refresh",
            headers={"origin": INDUS_BASE_URL, "referer": f"{INDUS_BASE_URL}/"},
        )

        if resp.status_code == 401:
            self._authenticated = False
            raise AuthenticationError("Session expired. Please login again.")

        if resp.status_code != 200:
            raise APIError(
                f"Token refresh failed: {resp.status_code}",
                status_code=resp.status_code,
                response_body=resp.text,
            )

        data = resp.json()
        result = RefreshResponse.model_validate(data)
        self._authenticated = True
        logger.debug("Token refreshed, expires in %ds", result.expires_in)
        return result

    def get_me(self) -> UserInfo:
        """Get current user info.

        Returns:
            UserInfo for the authenticated user.

        Raises:
            AuthenticationError: If not authenticated.
        """
        resp = self._client.get(
            f"{INDUS_BASE_URL}/api/auth/me",
            headers={"referer": f"{INDUS_BASE_URL}/"},
        )

        if resp.status_code == 401:
            self._authenticated = False
            raise AuthenticationError("Not authenticated")

        if resp.status_code != 200:
            raise APIError(
                f"Failed to get user info: {resp.status_code}",
                status_code=resp.status_code,
                response_body=resp.text,
            )

        data = resp.json()
        return UserInfo.model_validate(data)

    def save_session(self, path: str | Path) -> None:
        """Save session cookies to a file for later reuse.

        Args:
            path: File path to save the session data.
        """
        path = Path(path)
        cookies_data = []
        for cookie in self._client.cookies.jar:
            cookies_data.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
            })

        session_data = {
            "cookies": cookies_data,
            "authenticated": self._authenticated,
        }
        path.write_text(json.dumps(session_data, indent=2))
        logger.info("Session saved to %s", path)

    def load_session(self, path: str | Path) -> bool:
        """Load session cookies from a file.

        Args:
            path: File path to load the session data from.

        Returns:
            True if session was loaded and is valid.

        Raises:
            AuthenticationError: If session file doesn't exist or is invalid.
        """
        path = Path(path)
        if not path.exists():
            raise AuthenticationError(f"Session file not found: {path}")

        try:
            session_data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            raise AuthenticationError(f"Failed to load session: {e}")

        # Restore cookies
        for cookie_data in session_data.get("cookies", []):
            self._client.cookies.set(
                cookie_data["name"],
                cookie_data["value"],
                domain=cookie_data.get("domain", ""),
                path=cookie_data.get("path", "/"),
            )

        # Verify the session is still valid
        try:
            self.refresh()
            self._authenticated = True
            logger.info("Session loaded and validated from %s", path)
            return True
        except (AuthenticationError, APIError):
            self._authenticated = False
            logger.warning("Loaded session is expired")
            return False

    def close(self) -> None:
        """Close the HTTP client if we own it."""
        if self._owns_client:
            self._client.close()

    def _refresh_csrf_token(self) -> None:
        """Fetch the latest CSRF token from the login flow."""
        if not self._flow_id:
            return

        resp = self._client.get(
            f"{LOGIN_BASE_URL}/api/flow/login",
            params={"id": self._flow_id},
        )
        if resp.status_code == 200:
            flow_data = resp.json()
            token = self._extract_csrf_token(flow_data)
            if token:
                self._csrf_token = token
                logger.debug("CSRF token refreshed")

    @staticmethod
    def _extract_csrf_token(flow_data: dict) -> str | None:
        """Extract CSRF token from Ory/Kratos flow data.

        The CSRF token is nested in the UI nodes of the flow response.
        """
        # Try direct csrf_token field
        if "csrf_token" in flow_data:
            return flow_data["csrf_token"]

        # Try nested in UI nodes (Ory/Kratos format)
        ui = flow_data.get("ui", {})
        nodes = ui.get("nodes", [])
        for node in nodes:
            attrs = node.get("attributes", {})
            if attrs.get("name") == "csrf_token":
                return attrs.get("value")

        # Try in the flow's action URL
        return None

    @staticmethod
    def _extract_error_message(body: dict) -> str:
        """Extract a human-readable error from an Ory/Kratos error response."""
        # Check UI messages
        ui = body.get("ui", {})
        messages = ui.get("messages", [])
        if messages:
            return "; ".join(m.get("text", str(m)) for m in messages)

        # Check node-level messages
        nodes = ui.get("nodes", [])
        for node in nodes:
            node_messages = node.get("messages", [])
            if node_messages:
                return "; ".join(m.get("text", str(m)) for m in node_messages)

        # Check top-level error
        error = body.get("error", {})
        if isinstance(error, dict):
            return error.get("message", str(error))
        return str(error)
