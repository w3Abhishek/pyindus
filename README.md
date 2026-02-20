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

## License

MIT
