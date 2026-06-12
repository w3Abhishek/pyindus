# PyIndus

A Python package for interacting with [Indus](https://indus.sarvam.ai), a ChatGPT alternative by Sarvam AI.

## Installation

```bash
pip install pyindus
```

Or with uv:

```bash
uv add pyindus
```

## Quick Start

`IndusClient` acts as a fully-featured, seamless SDK. It **automatically saves, loads, and refreshes sessions** for you.

### 1. Initial Login
Run this once to authenticate. The client will automatically save your session to `indus_session.json` by default.

```python
from pyindus import IndusClient

# Login with phone number
client = IndusClient()
client.login("+91XXXXXXXXXX")

# Enter the OTP received via SMS
client.verify_otp("123456")

# The session is now authenticated and saved automatically!
```

### 2. Immediate Re-use (Like an SDK)
Run this anywhere else in your project. Because the session was saved, the client automatically loads it on `__init__`. *If the token expires, the client will dynamically refresh it in the background.*

```python
from pyindus import IndusClient

# Automatically loads the previous session from 'indus_session.json'
client = IndusClient()

# Chat directly! No need to login again.
response = client.chat("What is quantum computing?")
print(response.answer)
```

## Integration Guide: Custom Paths

If you're building a web app or managing multiple users, you can specify individual session files.

```python
from pyindus import IndusClient

# Supply a unique path for the user's session
def handle_user_request(user_id, message):
    session_path = f"sessions/user_{user_id}.json"
    
    # Auto-loads and manages session in this specific file
    with IndusClient(session_file=session_path) as client:
        return client.chat(message)
```

## Advanced Usage

### Working with Specific Models
Indus supports different "Task Graphs" (models like Sarvam Think, Bulbul, etc.). By default, `IndusClient` selects the first available chat model automatically.

```python
from pyindus import IndusClient

with IndusClient() as client:
    # List available models
    models = client.get_models()
    for model in models:
        print(f"{model.name}: {model.description}")

    # Use a specific model
    response = client.chat("Explain gravity", task_graph_uid=models[-1].uid)
    print(response.answer)
```

### File Attachments

Upload files and attach them to your messages:

```python
from pyindus import IndusClient

with IndusClient() as client:
    # Upload a file
    attachment = client.upload_attachment("./document.pdf")
    
    # Chat with the attachment
    response = client.chat("Summarize this document", attachments=[attachment])
    print(response.answer)
```

### Session Management

```python
with IndusClient() as client:
    # List all sessions
    sessions = client.list_sessions()
    for s in sessions:
        print(f"{s.title} ({s.uid})")

    # Delete a session
    client.delete_session(session_uid)
    
    # Start fresh
    client.new_session()
```

## TUI Usage

Launch the interactive terminal UI with:

```bash
pyindus chat
```

### Features

- **Rich terminal interface** with styled panels, markdown rendering, and color-coded output
- **Slash commands**: `/auth`, `/model`, `/session`, `/history`, `/delete`, `/attach`, `/new`, `/clear`, `/help`, `/exit`
- **File attachments**: Use `@path/to/file` in messages or `/attach file.txt` to upload files
- **Session history**: Browse and manage past chat sessions
- **Model picker**: List and switch between available AI models
- **Session persistence**: Automatically saves and loads sessions
- **Tool call display**: Shows search queries and tool usage during responses
- **Markdown rendering**: Code blocks, lists, and formatting in responses

### Auth Flow

1. Launch with `pyindus chat`
2. Run `/auth` to start the login flow
3. Enter your phone number with country code (e.g., `+918874163264`)
4. Enter the OTP received via SMS
5. Start chatting!

### File Attachments

Attach files to your messages using the `@` prefix:

```
you (Sarvam Think) > @./report.pdf summarize this document
```

Or use the `/attach` command to queue files before sending:

```
you (Sarvam Think) > /attach screenshot.png
Attached: screenshot.png (45KB) (1 file pending)
you (Sarvam Think) > what's in this image?
```

### Session Management

```
/history    - List recent chat sessions
/delete     - Delete the current session
/new        - Start a fresh session
/session    - Show current session info
```

### Screenshot

```
╭──────────────────────────────────╮
│ ░▄▀▀▄░█░░█░▀█▀░█▀▀▄░█▀▄░█░▒█░█▀▀ │
│ ░█▄▄█░█▄▄█░▒█░░█░▒█░█░█░█░▒█░▀▀▄ │
│ ░█░░░░▄▄▄▀░▄█▄░▀░░▀░▀▀░░▀▀▀░▀▀▀  │
╰──────────────────────────────────╯
Welcome to PyIndus TUI
Type /help for commands, or just start chatting.

you (Sarvam Think) > What is 2+2?

╭────────────────────────── you ──────────────────────────╮
│ What is 2+2?                                           │
╰────────────────────────────────────────────────────────╯

  Indus is thinking...

╭────────────────────────── indus ────────────────────────╮
│ 4                                                      │
╰────────────────────────────────────────────────────────╯
  0.9s
```

---

## Development

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/pyindus.git
cd pyindus

# Install with dev dependencies (using uv)
uv sync

# Or with pip
pip install -e ".[dev]"
```

### Project Structure

```
pyindus/
├── src/pyindus/
│   ├── __init__.py       # Package exports
│   ├── auth.py           # Ory/Kratos authentication flow
│   ├── chat.py           # Chat API operations (prompts, sessions, attachments)
│   ├── client.py         # High-level SDK client
│   ├── cli.py            # CLI entrypoints (pyindus auth/chat)
│   ├── exceptions.py     # Custom exception hierarchy
│   ├── models.py         # Pydantic models for API responses
│   └── tui.py            # Rich terminal UI
├── tests/
│   ├── test_auth.py      # Auth unit tests (mocked)
│   ├── test_chat.py      # Chat API unit tests (mocked)
│   ├── test_client.py    # Client integration tests (mocked)
│   ├── test_live.py      # Live API tests (requires real session)
│   ├── test_models.py    # Pydantic model tests
│   └── test_tui.py       # TUI command and rendering tests
├── pyproject.toml
└── uv.lock
```

### Running Tests

```bash
# Run all tests (mocked, no API calls)
uv run pytest tests/ -v

# Run tests excluding live API tests
uv run pytest tests/ -m "not live" -v

# Run only live tests (requires valid indus_session.json)
uv run pytest tests/ -m "live" -v

# Run with coverage
uv run pytest tests/ --cov=pyindus --cov-report=term-missing

# Run a specific test file
uv run pytest tests/test_tui.py -v
```

### Test Categories

- **Unit tests** (`test_auth.py`, `test_chat.py`, `test_client.py`, `test_models.py`, `test_tui.py`): Use `respx` to mock HTTP calls. Safe to run offline, no API credentials needed.
- **Live tests** (`test_live.py`): Make real API calls. Require a valid `indus_session.json` in the project root. Marked with `@pytest.mark.live`.

### Linting & Type Checking

```bash
# Install dev tools
uv add --dev ruff mypy

# Format code
uv run ruff format src/ tests/

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/pyindus/
```

### Building the Package

```bash
# Install build tool
uv add --dev build

# Build sdist and wheel
uv run python -m build

# Output will be in dist/
ls dist/
# pyindus-0.1.0.tar.gz
# pyindus-0.1.0-py3-none-any.whl
```

### Publishing to PyPI

```bash
# Install twine
uv add --dev twine

# Upload to PyPI (requires PyPI account and API token)
uv run twine upload dist/*

# Or upload to Test PyPI first
uv run twine upload --repository testpypi dist/*
```

**PyPI Setup:**
1. Create an account at [pypi.org](https://pypi.org)
2. Generate an API token at [pypi.org/manage/account/token/](https://pypi.org/manage/account/token/)
3. Configure `~/.pypirc`:
   ```ini
   [pypi]
   username = __token__
   password = pypi-YOUR_API_TOKEN
   ```

**Using uv for publishing:**
```bash
# uv can publish directly
uv publish dist/*
```

### Offline Testing

All unit tests run completely offline. The tests use `respx` to mock all HTTP requests, so no network access or API credentials are needed.

```bash
# This runs entirely offline - no API calls made
uv run pytest tests/ -m "not live" -v
```

To verify tests are truly offline, you can disconnect from the network or use a firewall:

```bash
# Block network access for tests (Linux)
uv run pytest tests/ -m "not live" -v  # All 100+ tests pass offline
```

### Version Bumping

Update the version in `pyproject.toml`:

```toml
[project]
version = "0.2.0"  # Update this
```

Then rebuild and publish:

```bash
uv run python -m build
uv run twine upload dist/*
```

## License

MIT
