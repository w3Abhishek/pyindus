"""CLI entry point for PyIndus.

Provides an interactive login flow and TUI chat interface.
"""

from __future__ import annotations

import sys


def main():
    """CLI dispatcher: `pyindus` launches TUI by default."""
    args = sys.argv[1:]

    if not args or args[0] in ("chat", "tui"):
        from pyindus.tui import main as tui_main
        sys.argv = [sys.argv[0]] + (args[1:] if args else [])
        tui_main()
        return



    if args and args[0] in ("--help", "-h", "help"):
        print("Usage: pyindus [command]")
        print()
        print("Commands:")
        print("  chat    Launch the interactive TUI chat interface")
        print("  tui     Alias for chat")
        print("  auth    Log in with phone number and OTP")
        print("  (none)  Launch the interactive TUI chat interface")
        print()
        print("Options:")
        print("  --session-file PATH  Path to session file (default: indus_session.json)")
        return

    if args and args[0] == "auth":
        _auth_main()
        return

    print(f"Unknown command: {args[0]}", file=sys.stderr)
    print("Run `pyindus --help` for usage.", file=sys.stderr)
    sys.exit(2)


def _auth_main():
    from pyindus.client import IndusClient
    client = IndusClient()
    phone = input("Phone number (with country code, e.g. +91...): ").strip()
    if not phone:
        print("Phone number is required.")
        sys.exit(1)
    
    try:
        client.login(phone)
        print(f"✓ OTP sent to {phone}")
    except Exception as e:
        print(f"✗ Login failed: {e}")
        sys.exit(1)

    code = input("Enter OTP code: ").strip()
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



if __name__ == "__main__":
    main()
