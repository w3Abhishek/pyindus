"""Pydantic models for Indus API responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class UserInfo(BaseModel):
    """User info from /api/auth/me."""

    sub: str
    email: str = ""
    name: str = ""
    token_expires_at: int = Field(alias="tokenExpiresAt")
    token_expires_in: int = Field(alias="tokenExpiresIn")

    model_config = {"populate_by_name": True}


class ChatAccount(BaseModel):
    """Chat account info from /api/chat/account/me."""

    uid: str
    first_name: str | None = None
    last_name: str | None = None
    full_name: str | None = None
    email: str = ""
    dp: str | None = None


class TaskGraph(BaseModel):
    """Available AI model/task graph."""

    uid: str
    name: str
    description: str = ""
    online: bool = False
    online_sort_order: int = 0
    favicon_light: str | None = None
    favicon_dark: str | None = None
    nodes: dict | None = None
    attachment_mime: list[str] = Field(default_factory=list, alias="attachmentMime")
    max_attachment_count: int | None = Field(default=None, alias="maxAttachmentCount")
    max_attachment_size: int | None = Field(default=None, alias="maxAttachmentSize")
    prompt_improvement_agent_uid: str | None = Field(default=None, alias="prompt_improvement_agent_uid")
    can_edit_artefact: bool = Field(default=False, alias="canEditArtefact")
    init_json_schema: dict | None = Field(default=None, alias="initJsonSchema")

    model_config = {"populate_by_name": True}


class ChatSession(BaseModel):
    """Chat session metadata."""

    uid: str
    title: str = ""
    task_graph_uid: str = ""
    task_graph_version: int | None = None
    created_at: str = ""
    role: str = ""


class Step(BaseModel):
    """Individual step in a prompt response.

    Step types (determined by 't' field):
        0  - Thinking/reasoning content
        20 - Separator/newline
        17 - Tool call (search, etc.)
        15 - Tool result
    """

    node_uid: str | None = None
    t: int = 0
    content: str | None = None
    # Tool call fields
    id: str | None = None
    name: str | None = None
    arg: str | None = None
    mcp_uid: str | None = None

    @property
    def is_thinking(self) -> bool:
        return self.t == 0

    @property
    def is_tool_call(self) -> bool:
        return self.t == 17

    @property
    def is_tool_result(self) -> bool:
        return self.t == 15

    @property
    def is_separator(self) -> bool:
        return self.t == 20


class PromptResponse(BaseModel):
    """Full response from /api/chat/prompt/prompt."""

    human_turn_uid: str = Field(alias="humanTurnUid")
    agent_turn_uid: str = Field(alias="agentTurnUid")
    steps: list[Step] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    @property
    def answer(self) -> str:
        """Extract the final text answer from the steps.

        The final answer is typically the last thinking step (t=0) that
        contains the synthesized response after all tool calls.
        """
        answer_parts: list[str] = []
        # Find the last group of thinking steps after tool results
        last_tool_result_idx = -1
        for i, step in enumerate(self.steps):
            if step.is_tool_result:
                last_tool_result_idx = i

        # Collect all thinking content after the last tool result
        start_idx = last_tool_result_idx + 1 if last_tool_result_idx >= 0 else 0
        for step in self.steps[start_idx:]:
            if step.is_thinking and step.content:
                answer_parts.append(step.content)
            elif step.is_separator and step.content:
                answer_parts.append(step.content)

        return "".join(answer_parts).strip()

    @property
    def thinking(self) -> str:
        """Extract thinking/reasoning content (before the final answer)."""
        parts: list[str] = []
        for step in self.steps:
            if step.is_thinking and step.content:
                parts.append(step.content)
            elif step.is_tool_call:
                break  # Stop at first tool call
        return "".join(parts).strip()

    @property
    def tool_calls(self) -> list[Step]:
        """Get all tool call steps."""
        return [s for s in self.steps if s.is_tool_call]

    @property
    def tool_results(self) -> list[Step]:
        """Get all tool result steps."""
        return [s for s in self.steps if s.is_tool_result]


class RefreshResponse(BaseModel):
    """Response from /api/auth/refresh."""

    success: bool
    expires_in: int = Field(alias="expiresIn")
    token_expires_at: int = Field(alias="tokenExpiresAt")

    model_config = {"populate_by_name": True}


class Config(BaseModel):
    """Platform configuration from /api/config."""

    voice_mode_enabled: bool = Field(default=False, alias="voiceModeEnabled")
    voice_mode_environment: str = Field(default="prod", alias="voiceModeEnvironment")
    hidden_task_graphs_mobile: list[str] = Field(default_factory=list, alias="hiddenTaskGraphsMobile")

    model_config = {"populate_by_name": True}
