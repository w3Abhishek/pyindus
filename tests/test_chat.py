"""Tests for the chat module."""

import httpx
import pytest
import respx

from pyindus.chat import IndusChat, INDUS_BASE_URL
from pyindus.exceptions import APIError, AuthenticationError, SessionError


# ── Sample response data ─────────────────────────────────────────

SAMPLE_TASK_GRAPHS = [
    {
        "uid": "ef571b75-1cc7-4397-a6fd-e4a45fae154a",
        "name": "Sarvam Think",
        "description": "Router -> adversarial/chat/think_web",
        "online": True,
        "online_sort_order": 0,
        "attachmentMime": [],
        "canEditArtefact": False,
    },
]

SAMPLE_TASK_GRAPH_DETAIL = {
    "uid": "ef571b75-1cc7-4397-a6fd-e4a45fae154a",
    "name": "Sarvam Think",
    "description": "Router -> adversarial/chat/think_web",
    "online": True,
    "online_sort_order": 0,
    "favicon_light": None,
    "favicon_dark": None,
    "nodes": {"start": "47442e30-70b4-46d5-936d-34a067d9b2a9"},
    "attachmentMime": [],
    "maxAttachmentCount": None,
    "maxAttachmentSize": None,
    "canEditArtefact": False,
}

SAMPLE_SESSIONS = [
    {
        "uid": "01KHYA5REP9CYPDT69GHQM5T5A",
        "title": "Quantum Leap by Google Cloud",
        "task_graph_uid": "ef571b75-1cc7-4397-a6fd-e4a45fae154a",
        "task_graph_version": 2,
        "created_at": "2026-02-20T19:59:35.384330Z",
        "role": "owner",
    },
]

SAMPLE_PROMPT_RESPONSE = {
    "humanTurnUid": "01KHYA5RJ21H6Q83TF04BGH040",
    "agentTurnUid": "01KHYA5RJ2611MXBA47FF03739",
    "steps": [
        {"node_uid": None, "t": 0, "content": "Thinking..."},
        {"node_uid": None, "t": 20, "content": "\n"},
        {
            "node_uid": None,
            "t": 17,
            "id": "call_1",
            "name": "search",
            "arg": '{"query": "test"}',
            "mcp_uid": "mcp-1",
        },
        {"node_uid": None, "t": 15, "id": "call_1", "content": '{"results": []}'},
        {"node_uid": None, "t": 0, "content": "Here is the final answer."},
    ],
}

SAMPLE_ACCOUNT = {
    "uid": "01KHYA56W0FTF1G2ZK6RXB0EVA",
    "first_name": "Test User",
    "last_name": None,
    "full_name": "Test User",
    "email": "",
    "dp": None,
}

SAMPLE_CONFIG = {
    "voiceModeEnabled": False,
    "voiceModeEnvironment": "prod",
    "hiddenTaskGraphsMobile": ["tg_uid"],
}


# ── Tests ─────────────────────────────────────────────────────────


class TestGetTaskGraphs:
    @respx.mock
    def test_get_task_graphs(self):
        respx.get(f"{INDUS_BASE_URL}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=SAMPLE_TASK_GRAPHS)
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            graphs = chat.get_task_graphs()
            assert len(graphs) == 1
            assert graphs[0].name == "Sarvam Think"
            assert graphs[0].uid == "ef571b75-1cc7-4397-a6fd-e4a45fae154a"
        finally:
            client.close()

    @respx.mock
    def test_get_task_graphs_empty(self):
        respx.get(f"{INDUS_BASE_URL}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=[])
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            graphs = chat.get_task_graphs()
            assert graphs == []
        finally:
            client.close()

    @respx.mock
    def test_get_task_graph_detail(self):
        uid = "ef571b75-1cc7-4397-a6fd-e4a45fae154a"
        respx.get(f"{INDUS_BASE_URL}/api/chat/task-graphs/{uid}").mock(
            return_value=httpx.Response(200, json=SAMPLE_TASK_GRAPH_DETAIL)
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            graph = chat.get_task_graph(uid)
            assert graph.name == "Sarvam Think"
            assert graph.nodes is not None
        finally:
            client.close()


class TestCreateSession:
    @respx.mock
    def test_create_session(self):
        respx.post(f"{INDUS_BASE_URL}/api/chat/session").mock(
            return_value=httpx.Response(201, json="01KHYA5REP9CYPDT69GHQM5T5A")
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            sid = chat.create_session("ef571b75-1cc7-4397-a6fd-e4a45fae154a")
            assert sid == "01KHYA5REP9CYPDT69GHQM5T5A"
        finally:
            client.close()

    @respx.mock
    def test_create_session_auth_error(self):
        respx.post(f"{INDUS_BASE_URL}/api/chat/session").mock(
            return_value=httpx.Response(401, json={"error": "Not authenticated"})
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            with pytest.raises(AuthenticationError):
                chat.create_session("test-uid")
        finally:
            client.close()


class TestSendPrompt:
    @respx.mock
    def test_send_prompt_success(self):
        respx.post(f"{INDUS_BASE_URL}/api/chat/prompt/prompt").mock(
            return_value=httpx.Response(200, json=SAMPLE_PROMPT_RESPONSE)
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            resp = chat.send_prompt("session-123", "What is AI?")
            assert resp.human_turn_uid == "01KHYA5RJ21H6Q83TF04BGH040"
            assert len(resp.steps) == 5
            assert resp.answer == "Here is the final answer."
            assert len(resp.tool_calls) == 1
        finally:
            client.close()

    @respx.mock
    def test_send_prompt_api_error(self):
        respx.post(f"{INDUS_BASE_URL}/api/chat/prompt/prompt").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            with pytest.raises(APIError):
                chat.send_prompt("session-123", "test")
        finally:
            client.close()


class TestListSessions:
    @respx.mock
    def test_list_sessions(self):
        respx.get(f"{INDUS_BASE_URL}/api/chat/session").mock(
            return_value=httpx.Response(200, json=SAMPLE_SESSIONS)
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            sessions = chat.list_sessions()
            assert len(sessions) == 1
            assert sessions[0].uid == "01KHYA5REP9CYPDT69GHQM5T5A"
            assert sessions[0].title == "Quantum Leap by Google Cloud"
        finally:
            client.close()

    @respx.mock
    def test_list_sessions_empty(self):
        respx.get(f"{INDUS_BASE_URL}/api/chat/session").mock(
            return_value=httpx.Response(200, json=[])
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            sessions = chat.list_sessions()
            assert sessions == []
        finally:
            client.close()


class TestAccountAndConfig:
    @respx.mock
    def test_get_account_me(self):
        respx.get(f"{INDUS_BASE_URL}/api/chat/account/me").mock(
            return_value=httpx.Response(200, json=SAMPLE_ACCOUNT)
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            account = chat.get_account_me()
            assert account.uid == "01KHYA56W0FTF1G2ZK6RXB0EVA"
            assert account.full_name == "Test User"
        finally:
            client.close()

    @respx.mock
    def test_get_config(self):
        respx.get(f"{INDUS_BASE_URL}/api/config").mock(
            return_value=httpx.Response(200, json=SAMPLE_CONFIG)
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            config = chat.get_config()
            assert config.voice_mode_enabled is False
            assert config.voice_mode_environment == "prod"
        finally:
            client.close()


class TestRequestErrorHandling:
    @respx.mock
    def test_401_raises_auth_error(self):
        respx.get(f"{INDUS_BASE_URL}/api/chat/account/me").mock(
            return_value=httpx.Response(401, json={"error": "Not authenticated"})
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            with pytest.raises(AuthenticationError, match="Not authenticated"):
                chat.get_account_me()
        finally:
            client.close()

    @respx.mock
    def test_500_raises_api_error(self):
        respx.get(f"{INDUS_BASE_URL}/api/chat/account/me").mock(
            return_value=httpx.Response(500, text="Server error")
        )

        client = httpx.Client()
        try:
            chat = IndusChat(client)
            with pytest.raises(APIError) as exc_info:
                chat.get_account_me()
            assert exc_info.value.status_code == 500
        finally:
            client.close()
