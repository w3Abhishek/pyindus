"""Tests for the TUI chat interface."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from pyindus.exceptions import AuthenticationError
from pyindus.tui import PyIndusTUI, _looks_like_markdown, FILE_REF_RE

# ── Sample data ─────────────────────────────────────────────────

INDUS_BASE = "https://indus.sarvam.ai"

SAMPLE_REFRESH = {
    "success": True,
    "expiresIn": 43200,
    "tokenExpiresAt": 1771660757000,
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
    {
        "uid": "tg-456",
        "name": "Sarvam Bulbul",
        "description": "Another model",
        "online": True,
        "online_sort_order": 1,
        "attachmentMime": [],
        "canEditArtefact": False,
    },
]

SAMPLE_PROMPT = {
    "humanTurnUid": "h1",
    "agentTurnUid": "a1",
    "steps": [
        {"t": 20, "content": "\nHello! How can I help?"},
        {"t": 0, "content": "The user is greeting me."},
    ],
}

SAMPLE_PROMPT_WITH_TOOLS = {
    "humanTurnUid": "h2",
    "agentTurnUid": "a2",
    "steps": [
        {"t": 0, "content": "Let me search for that."},
        {"t": 17, "id": "call_1", "name": "search", "arg": '{"query": "test"}', "mcp_uid": "mcp-1"},
        {"t": 15, "id": "call_1", "content": '{"results": []}'},
        {"t": 20, "content": "\nHere are the results."},
    ],
}


# ── Helpers ─────────────────────────────────────────────────────


def _make_tui(tmp_path):
    """Create a TUI instance with a temp session file."""
    session_file = tmp_path / "test_session.json"
    tui = PyIndusTUI(session_file=str(session_file))
    return tui


def _mock_authenticated(tui):
    """Mark TUI client as authenticated and set model."""
    tui.client._auth._authenticated = True
    tui.client._default_task_graph_uid = "tg-123"
    tui._current_model_name = "Sarvam Think"


# ── Tests ───────────────────────────────────────────────────────


class TestCommandParsing:
    """Test slash command parsing and dispatch."""

    def test_help_command(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/help")
        assert result is False

    def test_clear_command(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/clear")
        assert result is False

    def test_exit_command(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/exit")
        assert result is True

    def test_unknown_command(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/foobar")
        assert result is False

    def test_new_command_requires_auth(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/new")
        assert result is False

    def test_session_command(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/session")
        assert result is False

    def test_model_command_requires_auth(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/model")
        assert result is False

    def test_command_case_insensitive(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/EXIT")
        assert result is True


class TestUnauthenticatedState:
    """Test behavior when not authenticated."""

    def test_require_auth_returns_false_when_unauthenticated(self, tmp_path):
        tui = _make_tui(tmp_path)
        assert tui.client.is_authenticated is False
        result = tui._require_auth()
        assert result is False

    def test_new_shows_auth_message(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/new")
        assert result is False

    def test_handle_chat_skips_when_unauthenticated(self, tmp_path):
        tui = _make_tui(tmp_path)
        # Should not crash - _handle_chat calls _require_auth which returns False
        tui._handle_chat("Hello")


class TestAuthenticatedState:
    """Test behavior when authenticated."""

    @respx.mock
    def test_new_session_when_authenticated(self, tmp_path):
        respx.post(f"{INDUS_BASE}/api/chat/session").mock(
            return_value=httpx.Response(201, json="new-session-uid")
        )

        tui = _make_tui(tmp_path)
        _mock_authenticated(tui)
        result = tui._handle_command("/new")
        assert result is False

    @respx.mock
    def test_model_lists_available(self, tmp_path):
        # Single model: no interactive selection needed
        respx.get(f"{INDUS_BASE}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=[SAMPLE_TASK_GRAPHS[0]])
        )

        tui = _make_tui(tmp_path)
        _mock_authenticated(tui)

        result = tui._handle_command("/model")
        assert result is False

    @respx.mock
    def test_model_no_models(self, tmp_path):
        respx.get(f"{INDUS_BASE}/api/chat/task-graphs").mock(
            return_value=httpx.Response(200, json=[])
        )

        tui = _make_tui(tmp_path)
        _mock_authenticated(tui)
        result = tui._handle_command("/model")
        assert result is False


class TestMarkdownDetection:
    """Test the _looks_like_markdown helper."""

    def test_code_block(self):
        assert _looks_like_markdown("```python\nprint('hi')\n```") is True

    def test_headers(self):
        assert _looks_like_markdown("## Title") is True

    def test_bold(self):
        assert _looks_like_markdown("This is **bold**") is True

    def test_plain_text(self):
        assert _looks_like_markdown("Hello world") is False

    def test_list_dash(self):
        assert _looks_like_markdown("- item one") is True

    def test_numbered_list(self):
        assert _looks_like_markdown("1. first item") is True

    def test_underscore_bold(self):
        assert _looks_like_markdown("This is __bold__") is True


class TestChatRendering:
    """Test response rendering logic with real PromptResponse objects."""

    def test_simple_response_answer(self):
        from pyindus.models import PromptResponse

        resp = PromptResponse(**SAMPLE_PROMPT)
        assert resp.answer == "Hello! How can I help?"
        assert len(resp.tool_calls) == 0

    def test_tool_response_answer(self):
        from pyindus.models import PromptResponse

        resp = PromptResponse(**SAMPLE_PROMPT_WITH_TOOLS)
        assert resp.answer == "Here are the results."
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "search"

    def test_thinking_extraction(self):
        from pyindus.models import PromptResponse

        resp = PromptResponse(**SAMPLE_PROMPT_WITH_TOOLS)
        assert resp.thinking == "Let me search for that."

    def test_tool_results_extraction(self):
        from pyindus.models import PromptResponse

        resp = PromptResponse(**SAMPLE_PROMPT_WITH_TOOLS)
        assert len(resp.tool_results) == 1


class TestFileReferenceExtraction:
    """Test @file reference extraction from chat input."""

    def test_single_file_ref(self):
        tui = PyIndusTUI.__new__(PyIndusTUI)
        refs = tui._extract_file_refs("@./report.pdf summarize this")
        assert refs == ["./report.pdf"]

    def test_multiple_file_refs(self):
        tui = PyIndusTUI.__new__(PyIndusTUI)
        refs = tui._extract_file_refs("@file1.txt and @file2.py compare them")
        assert refs == ["file1.txt", "file2.py"]

    def test_no_file_refs(self):
        tui = PyIndusTUI.__new__(PyIndusTUI)
        refs = tui._extract_file_refs("just a plain message")
        assert refs == []

    def test_regex_matches(self):
        matches = FILE_REF_RE.findall("@path/to/file.txt hello")
        assert matches == ["path/to/file.txt"]

    def test_file_suggestions_for_at_query(self, tmp_path, monkeypatch):
        (tmp_path / "open.txt").write_text("hello")
        (tmp_path / "other.txt").write_text("hello")
        monkeypatch.chdir(tmp_path)

        tui = PyIndusTUI.__new__(PyIndusTUI)
        suggestions = tui._suggest_files("summarize @op")

        assert [p.name for p in suggestions] == ["open.txt"]


class TestAttachmentModel:
    """Test Attachment model creation."""

    def test_attachment_fields(self):
        from pyindus.models import Attachment

        att = Attachment(uid="uid-123", mime="text/plain", filename="test.txt", size=42)
        assert att.uid == "uid-123"
        assert att.mime == "text/plain"
        assert att.filename == "test.txt"
        assert att.size == 42
        assert att.is_uploading is False

    def test_attachment_alias(self):
        from pyindus.models import Attachment

        att = Attachment.model_validate({
            "uid": "uid-456",
            "mime": "image/png",
            "filename": "pic.png",
            "size": 1024,
            "isUploading": True,
        })
        assert att.is_uploading is True


class TestNewCommands:
    """Test the new TUI commands."""

    def test_history_requires_auth(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/history")
        assert result is False

    def test_delete_requires_auth(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/delete")
        assert result is False

    def test_delete_no_active_session(self, tmp_path):
        tui = _make_tui(tmp_path)
        _mock_authenticated(tui)
        result = tui._handle_command("/delete")
        assert result is False

    def test_attach_requires_args(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/attach")
        assert result is False

    def test_attach_file_not_found(self, tmp_path):
        tui = _make_tui(tmp_path)
        result = tui._handle_command("/attach /nonexistent/file.txt")
        assert result is False

    @respx.mock
    def test_history_lists_sessions(self, tmp_path):
        sessions = [
            {"uid": "s1", "title": "First Chat", "created_at": "2026-06-12T10:00:00"},
            {"uid": "s2", "title": "Second Chat", "created_at": "2026-06-12T11:00:00"},
        ]
        respx.get(f"{INDUS_BASE}/api/chat/session").mock(
            return_value=httpx.Response(200, json=sessions)
        )

        tui = _make_tui(tmp_path)
        _mock_authenticated(tui)
        result = tui._handle_command("/history")
        assert result is False

    @respx.mock
    def test_attach_uploads_file(self, tmp_path):
        test_file = tmp_path / "hello.txt"
        test_file.write_text("hello world")

        respx.post(f"{INDUS_BASE}/api/chat/attachments").mock(
            return_value=httpx.Response(201, text='"att-uid-123"')
        )

        tui = _make_tui(tmp_path)
        _mock_authenticated(tui)
        result = tui._handle_command(f"/attach {test_file}")
        assert result is False
        assert len(tui._pending_attachments) == 1
        assert tui._pending_attachments[0].uid == "att-uid-123"


class TestPendingAttachments:
    """Test pending attachments flow."""

    def test_pending_attachments_cleared_on_new(self, tmp_path):
        from pyindus.models import Attachment

        tui = _make_tui(tmp_path)
        _mock_authenticated(tui)
        tui._pending_attachments = [Attachment(uid="x", filename="x.txt")]

        with respx.mock:
            respx.post(f"{INDUS_BASE}/api/chat/session").mock(
                return_value=httpx.Response(201, json="new-sid")
            )
            tui._handle_command("/new")

        assert len(tui._pending_attachments) == 0

    def test_prompt_string_shows_attachment_count(self, tmp_path):
        from pyindus.models import Attachment

        tui = _make_tui(tmp_path)
        tui._current_model_name = "Sarvam Think"
        tui._pending_attachments = [
            Attachment(uid="a", filename="a.txt"),
            Attachment(uid="b", filename="b.png"),
        ]
        prompt = tui._prompt_string()
        assert "+2 files" in prompt

    def test_prompt_string_no_attachments(self, tmp_path):
        tui = _make_tui(tmp_path)
        tui._current_model_name = "Sarvam Think"
        prompt = tui._prompt_string()
        assert "+" not in prompt
