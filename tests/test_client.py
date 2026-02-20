"""Tests for the high-level IndusClient."""

import json
import tempfile
from pathlib import Path

import httpx
import pytest
import respx

from pyindus.client import IndusClient
from pyindus.exceptions import AuthenticationError, SessionError

# Add an autouse fixture to patch IndusClient's default session_file 
# so tests don't leak "indus_session.json" into the local dir or
# hit unmocked refresh endpoints during __init__.
@pytest.fixture(autouse=True)
def mock_session_file(tmp_path, monkeypatch):
    test_session_file = tmp_path / "test_session.json"
    
    # We monkeypatch the default arg of IndusClient.__init__
    original_init = IndusClient.__init__
    def mocked_init(self, session_file=None):
        original_init(self, session_file=session_file or test_session_file)
        
    monkeypatch.setattr(IndusClient, "__init__", mocked_init)
    return test_session_file


# ── Sample data ───────────────────────────────────────────────────

INDUS_BASE = "https://indus.sarvam.ai"
LOGIN_BASE = "https://login.sarvam.ai"

SAMPLE_LOGIN_FLOW = {
    "id": "flow-123",
    "ui": {
        "nodes": [
            {"attributes": {"name": "csrf_token", "value": "csrf-test"}},
        ],
        "messages": [],
    },
}

SAMPLE_REFRESH = {
    "success": True,
    "expiresIn": 43200,
    "tokenExpiresAt": 1771660757000,
}

SAMPLE_USER = {
    "sub": "user-123",
    "email": "test@test.com",
    "name": "Test User",
    "tokenExpiresAt": 1771660757000,
    "tokenExpiresIn": 43200,
}

SAMPLE_TASK_GRAPHS = [
    {
        "uid": "tg-123",
        "name": "Sarvam Think",
        "description": "Test model",
        "online": True,
        "online_sort_order": 0,
        "attachmentMime": [],
        "canEditArtefact": False,
    },
]

SAMPLE_PROMPT = {
    "humanTurnUid": "h1",
    "agentTurnUid": "a1",
    "steps": [
        {"t": 0, "content": "Hello! Here is my response."},
    ],
}

SAMPLE_SESSIONS = [
    {
        "uid": "session-123",
        "title": "Test Session",
        "task_graph_uid": "tg-123",
        "task_graph_version": 1,
        "created_at": "2026-02-20T19:59:35Z",
        "role": "owner",
    },
]


# ── Tests ─────────────────────────────────────────────────────────


class TestClientContextManager:
    def test_context_manager(self):
        with IndusClient() as client:
            assert client is not None
        # After exit, client should be closed (no explicit assertion needed,
        # just verify no exceptions)


class TestClientAuth:
    @respx.mock
    def test_full_login_flow(self):
        # Mock login flow
        respx.post(f"{LOGIN_BASE}/api/flow/login").mock(
            return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW)
        )
        login_route = respx.post(
            url__startswith=f"{LOGIN_BASE}/identity/self-service/login"
        )
        login_route.side_effect = [
            httpx.Response(303, headers={"location": "/"}),
            httpx.Response(303, headers={"location": INDUS_BASE}),
        ]
        respx.get(url__startswith=f"{LOGIN_BASE}/api/flow/login").mock(
            return_value=httpx.Response(200, json=SAMPLE_LOGIN_FLOW)
        )
        respx.get(f"{INDUS_BASE}/").mock(return_value=httpx.Response(200))
        respx.post(f"{INDUS_BASE}/api/auth/refresh").mock(
            return_value=httpx.Response(200, json=SAMPLE_REFRESH)
        )
        respx.get(f"{INDUS_BASE}/api/auth/me").mock(
            return_value=httpx.Response(200, json=SAMPLE_USER)
        )
        respx.get(f"{INDUS_BASE}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=SAMPLE_TASK_GRAPHS)
        )

        with IndusClient() as client:
            flow_id = client.login("+911234567890")
            assert flow_id == "flow-123"

            user = client.verify_otp("123456")
            assert user.name == "Test User"
            assert client.is_authenticated is True


class TestClientChat:
    @respx.mock
    def test_chat_creates_session_automatically(self):
        respx.get(f"{INDUS_BASE}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=SAMPLE_TASK_GRAPHS)
        )
        respx.post(f"{INDUS_BASE}/api/chat/session").mock(
            return_value=httpx.Response(201, json="session-new")
        )
        respx.post(f"{INDUS_BASE}/api/chat/prompt/prompt").mock(
            return_value=httpx.Response(200, json=SAMPLE_PROMPT)
        )

        with IndusClient() as client:
            # Pretend we're authenticated
            client._auth._authenticated = True
            client._default_task_graph_uid = "tg-123"

            resp = client.chat("Hello!")
            assert resp.answer == "Hello! Here is my response."

    @respx.mock
    def test_chat_reuses_session(self):
        respx.post(f"{INDUS_BASE}/api/chat/prompt/prompt").mock(
            return_value=httpx.Response(200, json=SAMPLE_PROMPT)
        )

        with IndusClient() as client:
            client._auth._authenticated = True
            client._default_task_graph_uid = "tg-123"
            client._current_session_uid = "existing-session"

            resp = client.chat("Second message")
            assert resp.answer == "Hello! Here is my response."

    @respx.mock
    def test_chat_with_explicit_session(self):
        respx.post(f"{INDUS_BASE}/api/chat/prompt/prompt").mock(
            return_value=httpx.Response(200, json=SAMPLE_PROMPT)
        )

        with IndusClient() as client:
            client._auth._authenticated = True
            client._default_task_graph_uid = "tg-123"

            resp = client.chat("Hi", session_uid="explicit-session")
            assert resp.answer == "Hello! Here is my response."

    def test_chat_not_authenticated(self):
        with IndusClient() as client:
            with pytest.raises(AuthenticationError, match="Not authenticated"):
                client.chat("Hello")

    @respx.mock
    def test_new_session(self):
        respx.post(f"{INDUS_BASE}/api/chat/session").mock(
            return_value=httpx.Response(201, json="new-session-uid")
        )

        with IndusClient() as client:
            client._auth._authenticated = True
            client._default_task_graph_uid = "tg-123"

            sid = client.new_session()
            assert sid == "new-session-uid"

    @respx.mock
    def test_get_models(self):
        respx.get(f"{INDUS_BASE}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=SAMPLE_TASK_GRAPHS)
        )

        with IndusClient() as client:
            client._auth._authenticated = True
            models = client.get_models()
            assert len(models) == 1
            assert models[0].name == "Sarvam Think"

    @respx.mock
    def test_list_sessions(self):
        respx.get(f"{INDUS_BASE}/api/chat/session").mock(
            return_value=httpx.Response(200, json=SAMPLE_SESSIONS)
        )

        with IndusClient() as client:
            client._auth._authenticated = True
            sessions = client.list_sessions()
            assert len(sessions) == 1
            assert sessions[0].title == "Test Session"


class TestClientSessionPersistence:
    @respx.mock
    def test_save_and_load_session(self):
        respx.post(f"{INDUS_BASE}/api/auth/refresh").mock(
            return_value=httpx.Response(200, json=SAMPLE_REFRESH)
        )
        respx.get(f"{INDUS_BASE}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=SAMPLE_TASK_GRAPHS)
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            session_path = f.name

        try:
            # Save
            with IndusClient() as client:
                client._auth._authenticated = True
                client._auth.client.cookies.set(
                    "test", "value", domain="indus.sarvam.ai"
                )
                client.save_session(session_path)

            # Load
            with IndusClient() as client:
                result = client.load_session(session_path)
                assert result is True
                assert client.is_authenticated is True
        finally:
            Path(session_path).unlink(missing_ok=True)
