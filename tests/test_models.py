"""Tests for Pydantic models."""

from pyindus.models import (
    ChatAccount,
    ChatSession,
    Config,
    PromptResponse,
    RefreshResponse,
    Step,
    TaskGraph,
    UserInfo,
)


class TestUserInfo:
    def test_parse_from_api(self):
        data = {
            "sub": "22e84e9a-92c0-445b-9912-8faeddb8c088",
            "email": "",
            "name": "Abhishek Verma",
            "tokenExpiresAt": 1771660757000,
            "tokenExpiresIn": 43200,
        }
        user = UserInfo.model_validate(data)
        assert user.sub == "22e84e9a-92c0-445b-9912-8faeddb8c088"
        assert user.name == "Abhishek Verma"
        assert user.email == ""
        assert user.token_expires_at == 1771660757000
        assert user.token_expires_in == 43200

    def test_default_values(self):
        data = {
            "sub": "test-id",
            "tokenExpiresAt": 0,
            "tokenExpiresIn": 0,
        }
        user = UserInfo.model_validate(data)
        assert user.email == ""
        assert user.name == ""


class TestChatAccount:
    def test_parse_from_api(self):
        data = {
            "uid": "01KHYA56W0FTF1G2ZK6RXB0EVA",
            "first_name": "Abhishek Verma",
            "last_name": None,
            "full_name": "Abhishek Verma",
            "email": "",
            "dp": None,
        }
        account = ChatAccount.model_validate(data)
        assert account.uid == "01KHYA56W0FTF1G2ZK6RXB0EVA"
        assert account.first_name == "Abhishek Verma"
        assert account.last_name is None
        assert account.full_name == "Abhishek Verma"
        assert account.dp is None


class TestTaskGraph:
    def test_parse_from_api(self):
        data = {
            "uid": "ef571b75-1cc7-4397-a6fd-e4a45fae154a",
            "name": "Sarvam Think",
            "description": "Router -> adversarial/chat/think_web with search (v2: 3 modes to 3 nodes)",
            "online": True,
            "online_sort_order": 0,
            "favicon_light": None,
            "favicon_dark": None,
            "nodes": {"start": "47442e30-70b4-46d5-936d-34a067d9b2a9"},
            "attachmentMime": [],
            "maxAttachmentCount": None,
            "maxAttachmentSize": None,
            "prompt_improvement_agent_uid": None,
            "canEditArtefact": False,
            "initJsonSchema": None,
        }
        tg = TaskGraph.model_validate(data)
        assert tg.uid == "ef571b75-1cc7-4397-a6fd-e4a45fae154a"
        assert tg.name == "Sarvam Think"
        assert tg.online is True
        assert tg.attachment_mime == []
        assert tg.can_edit_artefact is False

    def test_minimal_data(self):
        data = {"uid": "test", "name": "Test Model"}
        tg = TaskGraph.model_validate(data)
        assert tg.uid == "test"
        assert tg.online is False


class TestChatSession:
    def test_parse_from_api(self):
        data = {
            "uid": "01KHYA5REP9CYPDT69GHQM5T5A",
            "title": "Quantum Leap by Google Cloud",
            "task_graph_uid": "ef571b75-1cc7-4397-a6fd-e4a45fae154a",
            "task_graph_version": 2,
            "created_at": "2026-02-20T19:59:35.384330Z",
            "role": "owner",
        }
        session = ChatSession.model_validate(data)
        assert session.uid == "01KHYA5REP9CYPDT69GHQM5T5A"
        assert session.title == "Quantum Leap by Google Cloud"
        assert session.role == "owner"


class TestStep:
    def test_thinking_step(self):
        step = Step(t=0, content="I am thinking...")
        assert step.is_thinking is True
        assert step.is_tool_call is False
        assert step.is_tool_result is False
        assert step.is_separator is False

    def test_tool_call_step(self):
        step = Step(
            t=17,
            id="call_123",
            name="search",
            arg='{"query": "test"}',
            mcp_uid="mcp-123",
        )
        assert step.is_tool_call is True
        assert step.is_thinking is False
        assert step.name == "search"

    def test_tool_result_step(self):
        step = Step(t=15, id="call_123", content='{"results": []}')
        assert step.is_tool_result is True

    def test_separator_step(self):
        step = Step(t=20, content="\n")
        assert step.is_separator is True


class TestPromptResponse:
    SAMPLE_RESPONSE = {
        "humanTurnUid": "01KHYA5RJ21H6Q83TF04BGH040",
        "agentTurnUid": "01KHYA5RJ2611MXBA47FF03739",
        "steps": [
            {"node_uid": None, "t": 0, "content": "Let me think about this..."},
            {"node_uid": None, "t": 20, "content": "\n"},
            {
                "node_uid": None,
                "t": 17,
                "id": "call_1",
                "name": "search",
                "arg": '{"query": "test"}',
                "mcp_uid": "mcp-1",
            },
            {
                "node_uid": None,
                "t": 15,
                "id": "call_1",
                "content": '{"results": ["result1"]}',
            },
            {
                "node_uid": None,
                "t": 0,
                "content": "Based on the search, here is the answer.",
            },
            {"node_uid": None, "t": 20, "content": "\n"},
            {
                "node_uid": None,
                "t": 0,
                "content": "\nThis is the detailed response with information.",
            },
        ],
    }

    def test_parse_from_api(self):
        resp = PromptResponse.model_validate(self.SAMPLE_RESPONSE)
        assert resp.human_turn_uid == "01KHYA5RJ21H6Q83TF04BGH040"
        assert resp.agent_turn_uid == "01KHYA5RJ2611MXBA47FF03739"
        assert len(resp.steps) == 7

    def test_answer_extraction(self):
        resp = PromptResponse.model_validate(self.SAMPLE_RESPONSE)
        answer = resp.answer
        # Should be the content after the last tool result
        assert "Based on the search" in answer
        assert "detailed response" in answer
        # Should NOT contain the initial thinking
        assert "Let me think" not in answer

    def test_thinking_extraction(self):
        resp = PromptResponse.model_validate(self.SAMPLE_RESPONSE)
        thinking = resp.thinking
        assert "Let me think about this" in thinking

    def test_tool_calls(self):
        resp = PromptResponse.model_validate(self.SAMPLE_RESPONSE)
        calls = resp.tool_calls
        assert len(calls) == 1
        assert calls[0].name == "search"

    def test_tool_results(self):
        resp = PromptResponse.model_validate(self.SAMPLE_RESPONSE)
        results = resp.tool_results
        assert len(results) == 1
        assert "result1" in results[0].content

    def test_simple_response_no_tools(self):
        data = {
            "humanTurnUid": "h1",
            "agentTurnUid": "a1",
            "steps": [
                {"t": 0, "content": "Hello! How can I help you?"},
            ],
        }
        resp = PromptResponse.model_validate(data)
        assert resp.answer == "Hello! How can I help you?"
        assert len(resp.tool_calls) == 0


class TestRefreshResponse:
    def test_parse_from_api(self):
        data = {
            "success": True,
            "expiresIn": 43200,
            "tokenExpiresAt": 1771660757000,
        }
        r = RefreshResponse.model_validate(data)
        assert r.success is True
        assert r.expires_in == 43200
        assert r.token_expires_at == 1771660757000


class TestConfig:
    def test_parse_from_api(self):
        data = {
            "voiceModeEnabled": False,
            "voiceModeEnvironment": "prod",
            "hiddenTaskGraphsMobile": ["tg_uid"],
        }
        config = Config.model_validate(data)
        assert config.voice_mode_enabled is False
        assert config.voice_mode_environment == "prod"
        assert config.hidden_task_graphs_mobile == ["tg_uid"]
