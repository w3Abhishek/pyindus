"""Live connection tests for the Indus API.

These tests actually connect to the Indus API and require valid
authentication. They are skipped by default.

To run:
    uv run pytest tests/test_live.py -v -m live

Before running, you need a valid session file. Create one via:
    uv run pyindus
"""

import os

import pytest

from pyindus.client import IndusClient


# Skip all tests in this module unless INDUS_LIVE_TEST is set
pytestmark = pytest.mark.live

SESSION_FILE = os.environ.get("INDUS_SESSION_FILE", "indus_session.json")


@pytest.fixture
def client():
    """Create a client with loaded session."""
    c = IndusClient()
    if not os.path.exists(SESSION_FILE):
        pytest.skip(f"Session file not found: {SESSION_FILE}")
    try:
        if not c.load_session(SESSION_FILE):
            pytest.skip("Session expired. Re-authenticate with: uv run pyindus")
    except Exception as e:
        pytest.skip(f"Failed to load session: {e}")
    yield c
    c.close()


class TestLiveAuth:
    def test_get_user_info(self, client):
        """Test that we can get user info with a valid session."""
        user = client.get_user_info()
        assert user.sub is not None
        assert user.name is not None
        print(f"  Authenticated as: {user.name} ({user.sub})")

    def test_refresh_auth(self, client):
        """Test that token refresh works."""
        result = client.refresh_auth()
        assert result.success is True
        assert result.expires_in > 0


class TestLiveChat:
    def test_get_models(self, client):
        """Test listing available models."""
        models = client.get_models()
        assert len(models) > 0
        for m in models:
            print(f"  Model: {m.name} ({m.uid})")

    def test_get_config(self, client):
        """Test getting platform config."""
        config = client.get_config()
        assert config is not None
        print(f"  Voice mode: {config.voice_mode_enabled}")

    def test_get_account(self, client):
        """Test getting chat account."""
        account = client.get_account()
        assert account.uid is not None
        print(f"  Account: {account.full_name} ({account.uid})")

    def test_chat(self, client):
        """Test sending a chat message."""
        response = client.chat("Say hello in one word.")
        assert response is not None
        assert response.human_turn_uid is not None
        assert response.agent_turn_uid is not None
        assert len(response.answer) > 0
        print(f"  Response: {response.answer[:200]}")

    def test_list_sessions(self, client):
        """Test listing sessions (after chat creates one)."""
        sessions = client.list_sessions()
        assert isinstance(sessions, list)
        print(f"  Sessions: {len(sessions)}")
        for s in sessions[:3]:
            print(f"    - {s.title} ({s.uid})")
