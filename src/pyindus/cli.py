"""CLI entry point for PyIndus.

Provides an interactive login flow.
"""

from __future__ import annotations

import sys


def main():
    """Interactive login and chat."""
    from pyindus.client import IndusClient

    client = IndusClient()

    print("╔══════════════════════════════════════╗")
    print("║        PyIndus - Indus Chat          ║")
    print("║     Powered by Sarvam AI             ║")
    print("╚══════════════════════════════════════╝")
    print()

    # Try loading existing session
    try:
        if client.load_session():
            user = client.get_user_info()
            print(f"✓ Session loaded. Welcome back, {user.name}!")
            _chat_loop(client)
            return
    except Exception:
        pass

    # Interactive login
    phone = input("Enter your phone number (with country code, e.g., +91...): ").strip()
    if not phone:
        print("Phone number is required.")
        sys.exit(1)

    try:
        client.login(phone)
        print(f"✓ OTP sent to {phone}")
    except Exception as e:
        print(f"✗ Login failed: {e}")
        sys.exit(1)

    code = input("Enter the OTP code: ").strip()
    if not code:
        print("OTP code is required.")
        sys.exit(1)

    try:
        user = client.verify_otp(code)
        print(f"✓ Welcome, {user.name}!")
        client.save_session()
        print("✓ Session saved for next time.")
    except Exception as e:
        print(f"✗ OTP verification failed: {e}")
        sys.exit(1)

    _chat_loop(client)


def _chat_loop(client):
    """Simple interactive chat loop."""
    print()
    print("Type your message (or 'quit' to exit, 'new' for new session):")
    print()

    while True:
        try:
            prompt = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not prompt:
            continue
        if prompt.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break
        if prompt.lower() == "new":
            client.new_session()
            print("✓ New session started.")
            continue

        try:
            response = client.chat(prompt)
            print(f"\nIndus: {response.answer}\n")
        except Exception as e:
            print(f"\n✗ Error: {e}\n")

    client.close()


if __name__ == "__main__":
    main()
