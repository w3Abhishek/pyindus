"""Chat operations module for Indus API.

Handles chat sessions, prompts, task graphs, and account operations.
"""

from __future__ import annotations

import logging
import uuid

import httpx

from pyindus.exceptions import APIError, AuthenticationError, SessionError
from pyindus.models import (
    ChatAccount,
    ChatSession,
    Config,
    PromptResponse,
    TaskGraph,
)

logger = logging.getLogger(__name__)

INDUS_BASE_URL = "https://indus.sarvam.ai"


class IndusChat:
    """Handles chat operations with the Indus API.

    This class requires an authenticated httpx.Client with valid
    session cookies. Use IndusAuth to authenticate first.
    """

    def __init__(self, http_client: httpx.Client):
        self._client = http_client

    def get_task_graphs(self, online_only: bool = True) -> list[TaskGraph]:
        """Get available AI models (task graphs).

        Args:
            online_only: If True, only return online/available models.

        Returns:
            List of available TaskGraph models.
        """
        params = {}
        if online_only:
            params["online"] = "true"

        resp = self._request("GET", "/api/chat/task-graphs", params=params)
        return [TaskGraph.model_validate(tg) for tg in resp.json()]

    def get_task_graph(self, uid: str) -> TaskGraph:
        """Get details of a specific task graph.

        Args:
            uid: The task graph UID.

        Returns:
            TaskGraph details.
        """
        resp = self._request("GET", f"/api/chat/task-graphs/{uid}")
        return TaskGraph.model_validate(resp.json())

    def create_session(self, task_graph_uid: str) -> str:
        """Create a new chat session.

        Args:
            task_graph_uid: UID of the task graph (model) to use.

        Returns:
            The session UID.
        """
        resp = self._request(
            "POST",
            "/api/chat/session",
            json={"task_graph_uid": task_graph_uid},
        )

        if resp.status_code != 201:
            raise SessionError(
                f"Failed to create session: {resp.status_code} {resp.text}"
            )

        session_uid = resp.json()
        if isinstance(session_uid, str):
            logger.info("Created session: %s", session_uid)
            return session_uid
        else:
            # The response might be a dict with a uid field
            uid = session_uid.get("uid", session_uid.get("id", str(session_uid)))
            logger.info("Created session: %s", uid)
            return uid

    def send_prompt(self, session_uid: str, prompt: str) -> PromptResponse:
        """Send a prompt to a chat session.

        Args:
            session_uid: The session UID.
            prompt: The user's message.

        Returns:
            PromptResponse containing the AI's response steps.
        """
        # Generate trace ID for the request
        trace_id = uuid.uuid4().hex[:32]

        resp = self._request(
            "POST",
            "/api/chat/prompt/prompt",
            json={
                "sessionUid": session_uid,
                "prompt": prompt,
            },
            extra_headers={
                "x-amzn-trace-id": f"Root=1-{trace_id[:8]}-{trace_id[8:32]};eru={session_uid}",
            },
            timeout=120.0,  # Prompts can take longer
        )

        return PromptResponse.model_validate(resp.json())

    def list_sessions(self, include_shares: bool = True) -> list[ChatSession]:
        """List all chat sessions.

        Args:
            include_shares: If True, include shared sessions.

        Returns:
            List of ChatSession objects.
        """
        params = {}
        if include_shares:
            params["include_shares"] = "true"

        resp = self._request("GET", "/api/chat/session", params=params)
        return [ChatSession.model_validate(s) for s in resp.json()]

    def get_account_me(self) -> ChatAccount:
        """Get chat account info.

        Returns:
            ChatAccount with user details.
        """
        resp = self._request("GET", "/api/chat/account/me")
        return ChatAccount.model_validate(resp.json())

    def get_config(self) -> Config:
        """Get platform configuration.

        Returns:
            Config with platform settings.
        """
        resp = self._request("GET", "/api/config")
        return Config.model_validate(resp.json())

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
        extra_headers: dict | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """Make an authenticated request to the Indus API.

        Args:
            method: HTTP method.
            path: API path (relative to INDUS_BASE_URL).
            params: Query parameters.
            json: JSON request body.
            extra_headers: Additional headers.
            timeout: Request timeout.

        Returns:
            httpx.Response

        Raises:
            AuthenticationError: If the request returns 401.
            APIError: If the request fails.
        """
        url = f"{INDUS_BASE_URL}{path}"
        headers = {
            "accept": "application/json, text/plain, */*",
            "origin": INDUS_BASE_URL,
            "referer": f"{INDUS_BASE_URL}/",
        }
        if extra_headers:
            headers.update(extra_headers)

        kwargs: dict = {"headers": headers}
        if params:
            kwargs["params"] = params
        if json is not None:
            kwargs["json"] = json
        if timeout:
            kwargs["timeout"] = timeout

        resp = self._client.request(method, url, **kwargs)

        if resp.status_code == 401:
            raise AuthenticationError("Not authenticated. Please login first.")

        if resp.status_code >= 400:
            raise APIError(
                f"API error {resp.status_code}: {resp.text}",
                status_code=resp.status_code,
                response_body=resp.text,
            )

        return resp
