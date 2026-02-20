"""High-level client for the Indus Chat API.

Combines auth and chat modules into a simple, user-friendly interface.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from pyindus.auth import IndusAuth
from pyindus.chat import IndusChat
from pyindus.exceptions import AuthenticationError, SessionError
from pyindus.models import (
    ChatAccount,
    ChatSession,
    Config,
    PromptResponse,
    TaskGraph,
    UserInfo,
)

logger = logging.getLogger(__name__)


class IndusClient:
    """High-level client for interacting with the Indus Chat API.

    Usage::

        # Interactive login
        client = IndusClient()
        client.login("+91XXXXXXXXXX")
        client.verify_otp("123456")

        # Chat
        response = client.chat("What is AI?")
        print(response.answer)

        # Save session for later
        client.save_session("session.json")

    Usage with context manager::

        with IndusClient() as client:
            client.load_session("session.json")
            response = client.chat("Hello!")
            print(response.answer)
    """

    def __init__(self, session_file: str | Path = "indus_session.json"):
        self.session_file = session_file
        self._http_client = httpx.Client(
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
        self._auth = IndusAuth(http_client=self._http_client)
        self._chat = IndusChat(http_client=self._http_client)
        self._default_task_graph_uid: str | None = None
        self._current_session_uid: str | None = None
        
        # Auto-load session if it exists to make it feel like an SDK
        try:
            self.load_session(self.session_file, quiet=True)
        except AuthenticationError:
            pass

    # ── Context Manager ──────────────────────────────────────────

    def __enter__(self) -> IndusClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ── Authentication ───────────────────────────────────────────

    def login(self, phone: str) -> str:
        """Start login flow with phone number.

        An OTP will be sent to the provided phone number via SMS.
        Call verify_otp() with the received code to complete login.

        Args:
            phone: Phone number with country code (e.g., "+918874163264").

        Returns:
            Flow ID for the login flow.
        """
        return self._auth.login(phone)

    def verify_otp(self, code: str) -> UserInfo:
        """Complete login with OTP code.

        Args:
            code: The OTP code received via SMS.

        Returns:
            UserInfo for the authenticated user.
        """
        user_info = self._auth.verify_otp(code)

        # Cache the default task graph
        try:
            models = self.get_models()
            if models:
                self._default_task_graph_uid = models[0].uid
                logger.info("Default model: %s", models[0].name)
        except Exception as e:
            logger.warning("Could not fetch models: %s", e)

        # Auto-save session to provide a seamless SDK experience
        self.save_session(self.session_file)
        return user_info

    def save_session(self, path: str | Path | None = None) -> None:
        """Save session cookies to disk for later reuse.

        Args:
            path: File path to save the session data. Uses the default if not provided.
        """
        self._auth.save_session(path or self.session_file)

    def load_session(self, path: str | Path | None = None, quiet: bool = False) -> bool:
        """Load a previously saved session.

        Args:
            path: File path to load the session data from. Uses the default if not provided.
            quiet: If True, suppress errors if file doesn't exist.

        Returns:
            True if session loaded and is still valid.
        """
        try:
            result = self._auth.load_session(path or self.session_file)
        except AuthenticationError:
            if quiet:
                return False
            raise

        if result:
            # Cache the default task graph
            try:
                models = self.get_models()
                if models:
                    self._default_task_graph_uid = models[0].uid
            except Exception as e:
                if not quiet:
                    logger.warning("Could not fetch models: %s", e)

        return result

    @property
    def is_authenticated(self) -> bool:
        """Whether the client is currently authenticated."""
        return self._auth.is_authenticated

    def get_user_info(self) -> UserInfo:
        """Get current user info.

        Returns:
            UserInfo for the authenticated user.
        """
        return self._auth.get_me()

    def refresh_auth(self):
        """Manually refresh the auth token."""
        return self._auth.refresh()

    # ── Chat ─────────────────────────────────────────────────────

    def chat(
        self,
        prompt: str,
        *,
        session_uid: str | None = None,
        task_graph_uid: str | None = None,
    ) -> PromptResponse:
        """Send a message and get a response.

        If no session_uid is provided, a new session will be created.
        If no task_graph_uid is provided, the default model is used.

        Args:
            prompt: The user message.
            session_uid: Optional existing session UID for conversation continuity.
            task_graph_uid: Optional task graph UID to specify which model to use.

        Returns:
            PromptResponse with the AI's response.
        """
        if not self._auth.is_authenticated:
            # Try to auto-refresh if we have cookies but token expired
            try:
                self._auth.refresh()
            except AuthenticationError:
                raise AuthenticationError(
                    "Not authenticated. Call login() and verify_otp() first."
                )

        # Auto-refresh proactively wrapped around the chat to handle expiration
        # IndusChat already handles throwing APIErrors, but we can catch 401s
        # and retry once if the token expired mid-session.

        # Determine task graph
        tg_uid = task_graph_uid or self._default_task_graph_uid
        if not tg_uid:
            models = self.get_models()
            if not models:
                raise SessionError("No models available")
            tg_uid = models[0].uid
            self._default_task_graph_uid = tg_uid

        # Use existing session or create a new one
        if session_uid:
            sid = session_uid
        elif self._current_session_uid:
            sid = self._current_session_uid
        else:
            sid = self._chat.create_session(tg_uid)
            self._current_session_uid = sid

        # Send prompt with auto-retry on 401
        try:
            return self._chat.send_prompt(sid, prompt)
        except AuthenticationError:
            # Token might have expired just now, try to refresh and retry
            logger.info("Session expired during chat. Attempting auto-refresh...")
            self._auth.refresh()
            # Save the newly refreshed session automatically
            self.save_session()
            return self._chat.send_prompt(sid, prompt)

    def new_session(self, task_graph_uid: str | None = None) -> str:
        """Create a new chat session explicitly.

        Args:
            task_graph_uid: Optional task graph UID. Uses default if not provided.

        Returns:
            The new session UID.
        """
        tg_uid = task_graph_uid or self._default_task_graph_uid
        if not tg_uid:
            models = self.get_models()
            if not models:
                raise SessionError("No models available")
            tg_uid = models[0].uid

        self._current_session_uid = self._chat.create_session(tg_uid)
        return self._current_session_uid

    def get_models(self) -> list[TaskGraph]:
        """Get available AI models.

        Returns:
            List of available TaskGraph models.
        """
        return self._chat.get_task_graphs(online_only=True)

    def list_sessions(self) -> list[ChatSession]:
        """List all chat sessions.

        Returns:
            List of ChatSession objects.
        """
        return self._chat.list_sessions()

    def get_account(self) -> ChatAccount:
        """Get chat account info.

        Returns:
            ChatAccount with user details.
        """
        return self._chat.get_account_me()

    def get_config(self) -> Config:
        """Get platform configuration.

        Returns:
            Config with platform settings.
        """
        return self._chat.get_config()

    # ── Cleanup ──────────────────────────────────────────────────

    def close(self) -> None:
        """Close the client and release resources."""
        self._auth.close()
