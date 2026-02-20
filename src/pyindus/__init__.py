"""PyIndus - Python package for Indus Chat API by Sarvam AI."""

from pyindus.client import IndusClient
from pyindus.auth import IndusAuth
from pyindus.models import (
    UserInfo,
    ChatAccount,
    TaskGraph,
    ChatSession,
    PromptResponse,
    Step,
    Config,
)
from pyindus.exceptions import (
    IndusError,
    AuthenticationError,
    SessionError,
    APIError,
)

__version__ = "0.1.0"

__all__ = [
    "IndusClient",
    "IndusAuth",
    "UserInfo",
    "ChatAccount",
    "TaskGraph",
    "ChatSession",
    "PromptResponse",
    "Step",
    "Config",
    "IndusError",
    "AuthenticationError",
    "SessionError",
    "APIError",
]
