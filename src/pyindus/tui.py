"""Interactive TUI chat interface for PyIndus.

Launch with `pyindus chat` for a rich terminal experience.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pyindus.client import IndusClient
from pyindus.exceptions import (
    AuthenticationError,
    IndusError,
)
from pyindus.models import Attachment

LOGO = r"""░▄▀▀▄░█░░█░▀█▀░█▀▀▄░█▀▄░█░▒█░█▀▀
░█▄▄█░█▄▄█░▒█░░█░▒█░█░█░█░▒█░▀▀▄
░█░░░░▄▄▄▀░▄█▄░▀░░▀░▀▀░░▀▀▀░▀▀▀ """

WELCOME = """[bold cyan]Welcome to PyIndus TUI[/bold cyan]
Type [bold]/help[/bold] for commands, or just start chatting.
Use [bold]@path/to/file[/bold] to attach files to your message.
"""

HELP_TEXT = """[bold]Commands[/bold]

  [bold cyan]/auth[/bold cyan]       Log in with phone number + OTP
  [bold cyan]/model[/bold cyan]      List and switch AI models
  [bold cyan]/session[/bold cyan]    Show current session info
  [bold cyan]/history[/bold cyan]    List recent chat sessions
  [bold cyan]/delete[/bold cyan]     Delete current session
  [bold cyan]/attach[/bold cyan]     Attach a file for next message
  [bold cyan]/new[/bold cyan]        Start a new chat session
  [bold cyan]/clear[/bold cyan]      Clear the screen
  [bold cyan]/help[/bold cyan]       Show this help
  [bold cyan]/exit[/bold cyan]       Exit the TUI

[bold]File Attachments[/bold]
  Type [bold]@path/to/file[/bold] in your message to attach files.
  Example: [dim]@./report.pdf summarize this document[/dim]
  Or use [bold]/attach file.txt[/bold] then send your message."""

AUTH_PROMPT_MSG = "[dim]Not authenticated. Run /auth to log in.[/dim]"

FILE_REF_RE = re.compile(r"@(\S+)")


class PyIndusTUI:
    """Interactive chat TUI for PyIndus."""

    def __init__(self, session_file: str = "indus_session.json"):
        self.console = Console()
        self.client = IndusClient(session_file=session_file)
        self._current_model_name: str | None = None
        self._models_cache = None
        self._pending_attachments: list[Attachment] = []

    # ── Startup ──────────────────────────────────────────────────

    def run(self) -> None:
        """Main entry point."""
        self._show_logo()
        self._show_welcome()

        if self.client.is_authenticated:
            self._show_auth_status()
            self._prefetch_models()
        else:
            self.console.print(AUTH_PROMPT_MSG)

        self._repl()

    def _show_logo(self) -> None:
        logo = Text(LOGO, style="bold cyan")
        self.console.print(Panel(logo, border_style="cyan", expand=False))

    def _show_welcome(self) -> None:
        self.console.print(WELCOME)

    def _show_auth_status(self) -> None:
        try:
            user = self.client.get_user_info()
            self.console.print(
                Panel(
                    f"[green]Authenticated as [bold]{user.name}[/bold][/green]",
                    border_style="green",
                    expand=False,
                )
            )
        except Exception:
            self.console.print(AUTH_PROMPT_MSG)

    def _prefetch_models(self) -> None:
        """Pre-fetch models so the first /model or chat is fast."""
        try:
            self._models_cache = self.client.get_models()
            if self._models_cache:
                self._current_model_name = self._models_cache[0].name
        except Exception:
            pass

    # ── REPL ─────────────────────────────────────────────────────

    def _repl(self) -> None:
        """Main read-eval-print loop."""
        while True:
            try:
                prompt_text = self._prompt_string()
                user_input = self.console.input(prompt_text).strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[bold]Goodbye![/bold]")
                break

            if not user_input:
                continue

            if user_input.startswith("/"):
                should_exit = self._handle_command(user_input)
                if should_exit:
                    break
                continue

            self._handle_chat(user_input)

    def _prompt_string(self) -> str:
        model_tag = self._current_model_name or "no model"
        attach_tag = ""
        if self._pending_attachments:
            n = len(self._pending_attachments)
            attach_tag = f" [+{n} file{'s' if n > 1 else ''}]"
        return f"[bold cyan]you[/bold cyan] [dim]({model_tag}{attach_tag})[/dim] > "

    # ── Commands ─────────────────────────────────────────────────

    def _handle_command(self, raw: str) -> bool:
        """Dispatch slash commands. Returns True if TUI should exit."""
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        dispatch = {
            "/auth": self._cmd_auth,
            "/model": self._cmd_model,
            "/session": self._cmd_session,
            "/history": self._cmd_history,
            "/delete": self._cmd_delete,
            "/attach": self._cmd_attach,
            "/new": self._cmd_new,
            "/clear": self._cmd_clear,
            "/help": self._cmd_help,
            "/exit": self._cmd_exit,
        }

        handler = dispatch.get(cmd)
        if handler is None:
            self.console.print(f"[red]Unknown command: {cmd}[/red] Type /help for available commands.")
            return False

        return handler(args)

    def _cmd_help(self, _args: str = "") -> bool:
        self.console.print(HELP_TEXT)
        return False

    def _cmd_clear(self, _args: str = "") -> bool:
        self.console.clear()
        return False

    def _cmd_exit(self, _args: str = "") -> bool:
        self.console.print("[bold]Goodbye![/bold]")
        return True

    def _cmd_new(self, _args: str = "") -> bool:
        try:
            if not self._require_auth():
                return False
            self.client.new_session()
            self._pending_attachments.clear()
            self.console.print("[green]New session started.[/green]")
        except IndusError as e:
            self._handle_error(e)
        return False

    def _cmd_session(self, _args: str = "") -> bool:
        table = Table(title="Session Info", border_style="cyan", show_header=False)
        table.add_column("Key", style="bold")
        table.add_column("Value")

        table.add_row("Authenticated", str(self.client.is_authenticated))

        if self.client.is_authenticated:
            try:
                user = self.client.get_user_info()
                table.add_row("User", user.name)
                table.add_row("Email", user.email or "(none)")
                expires_in = user.token_expires_in
                if expires_in > 3600:
                    table.add_row("Token expires in", f"{expires_in // 3600}h {(expires_in % 3600) // 60}m")
                else:
                    table.add_row("Token expires in", f"{expires_in // 60}m")
            except Exception:
                table.add_row("User", "[red]Could not fetch[/red]")

        model = self._current_model_name or "(none)"
        table.add_row("Model", model)
        table.add_row("Session file", str(self.client.session_file))

        if self._pending_attachments:
            for a in self._pending_attachments:
                table.add_row("Attachment", f"{a.filename} ({a.size} bytes)")

        self.console.print(table)
        return False

    def _cmd_history(self, _args: str = "") -> bool:
        if not self._require_auth():
            return False

        try:
            sessions = self.client.list_sessions()
        except IndusError as e:
            self._handle_error(e)
            return False

        if not sessions:
            self.console.print("[dim]No chat sessions found.[/dim]")
            return False

        table = Table(title="Chat History", border_style="cyan")
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Title", style="bold")
        table.add_column("Created", style="dim")
        table.add_column("UID", style="dim", max_width=26)

        for i, s in enumerate(sessions[:20], 1):
            created = s.created_at[:16].replace("T", " ") if s.created_at else "?"
            table.add_row(str(i), s.title or "(untitled)", created, s.uid)

        self.console.print(table)
        self.console.print(f"[dim]  Showing {min(len(sessions), 20)} of {len(sessions)} sessions[/dim]")
        return False

    def _cmd_delete(self, _args: str = "") -> bool:
        if not self._require_auth():
            return False

        if not self.client._current_session_uid:
            self.console.print("[yellow]No active session to delete.[/yellow]")
            return False

        try:
            confirm = self.console.input(
                f"[bold red]Delete current session ({self.client._current_session_uid[:12]}...)? [y/N]: [/bold red]"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False

        if confirm != "y":
            self.console.print("[dim]Cancelled.[/dim]")
            return False

        try:
            self.client.delete_session()
            self.console.print("[green]Session deleted.[/green]")
        except IndusError as e:
            self._handle_error(e)

        return False

    def _cmd_attach(self, args: str = "") -> bool:
        if not args:
            self.console.print("[red]Usage: /attach <file_path>[/red]")
            return False

        file_path = args.strip()
        path = Path(file_path)

        if not path.exists():
            self.console.print(f"[red]File not found: {file_path}[/red]")
            return False

        if not self._require_auth():
            return False

        self.console.print(f"[dim]Uploading {path.name} ({path.stat().st_size} bytes)...[/dim]")
        try:
            attachment = self.client.upload_attachment(path)
            self._pending_attachments.append(attachment)
            self.console.print(
                f"[green]Attached: {attachment.filename} ({attachment.size} bytes) "
                f"[dim]({len(self._pending_attachments)} file{'s' if len(self._pending_attachments) > 1 else ''} pending)[/dim][/green]"
            )
        except IndusError as e:
            self._handle_error(e)

        return False

    def _cmd_model(self, _args: str = "") -> bool:
        if not self._require_auth():
            return False

        try:
            models = self.client.get_models()
        except IndusError as e:
            self._handle_error(e)
            return False

        if not models:
            self.console.print("[yellow]No models available.[/yellow]")
            return False

        self._models_cache = models

        table = Table(title="Available Models", border_style="cyan")
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Name", style="bold")
        table.add_column("Description", style="dim")
        table.add_column("Status", width=8)

        for i, m in enumerate(models, 1):
            status = "[green]online[/green]" if m.online else "[red]offline[/red]"
            table.add_row(str(i), m.name, m.description[:60] or "-", status)

        self.console.print(table)

        if len(models) == 1:
            self._current_model_name = models[0].name
            self.console.print(f"[green]Using: {models[0].name}[/green]")
            return False

        try:
            choice = self.console.input(
                f"[dim]Select model (1-{len(models)}) or press Enter to keep current: [/dim]"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return False

        if not choice:
            return False

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                self._current_model_name = models[idx].name
                self.client._default_task_graph_uid = models[idx].uid
                self.client.new_session(models[idx].uid)
                self.console.print(f"[green]Switched to: {models[idx].name}[/green]")
            else:
                self.console.print("[red]Invalid selection.[/red]")
        except ValueError:
            self.console.print("[red]Please enter a number.[/red]")

        return False

    def _cmd_auth(self, _args: str = "") -> bool:
        """Interactive phone + OTP auth flow."""
        try:
            phone = self.console.input("[bold cyan]Phone number (with country code, e.g. +91...): [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            return False

        if not phone:
            self.console.print("[red]Phone number required.[/red]")
            return False

        self.console.print("[dim]Sending OTP...[/dim]")
        try:
            self.client.login(phone)
        except IndusError as e:
            self._handle_error(e)
            return False

        self.console.print("[green]OTP sent![/green]")
        try:
            code = self.console.input("[bold cyan]Enter OTP code: [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            return False

        if not code:
            self.console.print("[red]OTP code required.[/red]")
            return False

        self.console.print("[dim]Verifying...[/dim]")
        try:
            user = self.client.verify_otp(code)
        except IndusError as e:
            self._handle_error(e)
            return False

        self.console.print(Panel(
            f"[green]Logged in as [bold]{user.name}[/bold][/green]",
            border_style="green",
            expand=False,
        ))
        self._prefetch_models()
        return False

    # ── Chat ─────────────────────────────────────────────────────

    def _handle_chat(self, prompt: str) -> None:
        if not self._require_auth():
            return

        attachments = list(self._pending_attachments)
        inline_files = self._extract_file_refs(prompt)
        prompt_clean = FILE_REF_RE.sub("", prompt).strip()

        for fp in inline_files:
            path = Path(fp)
            if not path.exists():
                self.console.print(f"[red]File not found: {fp}[/red]")
                continue
            self.console.print(f"[dim]Uploading {path.name}...[/dim]")
            try:
                att = self.client.upload_attachment(path)
                attachments.append(att)
            except IndusError as e:
                self._handle_error(e)
                return

        self._pending_attachments.clear()

        self.console.print()
        self.console.print(Panel(
            Markdown(prompt_clean) if _looks_like_markdown(prompt_clean) else prompt_clean,
            title="[bold cyan]you[/bold cyan]",
            border_style="cyan",
            expand=True,
        ))

        if attachments:
            file_list = ", ".join(a.filename for a in attachments)
            self.console.print(f"[dim]  Attached: {file_list}[/dim]")

        start = time.monotonic()
        self.console.print("[dim]  Indus is thinking...[/dim]")

        try:
            response = self.client.chat(
                prompt_clean,
                attachments=attachments if attachments else None,
            )
        except AuthenticationError:
            self.console.print(AUTH_PROMPT_MSG)
            return
        except IndusError as e:
            self._handle_error(e)
            return

        elapsed = time.monotonic() - start
        self._render_response(response, elapsed)

    def _extract_file_refs(self, text: str) -> list[str]:
        """Extract @file references from the input text."""
        return FILE_REF_RE.findall(text)

    def _render_response(self, response, elapsed: float) -> None:
        """Render the PromptResponse steps as rich panels."""
        answer = response.answer
        if answer:
            self.console.print()
            self.console.print(Panel(
                Markdown(answer),
                title="[bold green]indus[/bold green]",
                border_style="green",
                expand=True,
            ))

        tool_calls = response.tool_calls
        if tool_calls:
            self.console.print()
            self.console.print("[dim]  Tools used:[/dim]")
            for tc in tool_calls:
                name = tc.name or "unknown"
                try:
                    arg_data = json.loads(tc.arg) if tc.arg else {}
                except (json.JSONDecodeError, TypeError):
                    arg_data = {}
                if name == "search":
                    query = arg_data.get("query", "")
                    search_type = arg_data.get("search_type", "")
                    detail = f"[dim]{search_type}[/dim] " if search_type else ""
                    detail += query[:60]
                elif name == "extract_content":
                    detail = f"citation #{arg_data.get('citation_id', '?')}"
                else:
                    detail = (tc.arg or "")[:60]
                self.console.print(f"    [yellow]>[/yellow] {name}([dim]{detail}[/dim])")

        timing = f"[dim]{elapsed:.1f}s[/dim]"
        steps_info = f" [dim]({len(response.steps)} steps)[/dim]" if response.tool_calls else ""
        self.console.print(f"  {timing}{steps_info}")

    def _handle_error(self, exc: Exception) -> None:
        self.console.print(f"[bold red]Error:[/bold red] {exc}")

    # ── Helpers ──────────────────────────────────────────────────

    def _require_auth(self) -> bool:
        if self.client.is_authenticated:
            return True
        try:
            self.client.refresh_auth()
            return True
        except AuthenticationError:
            self.console.print(AUTH_PROMPT_MSG)
            return False


def _looks_like_markdown(text: str) -> bool:
    indicators = ["```", "## ", "- ", "1. ", "**", "__"]
    return any(ind in text for ind in indicators)


def main() -> None:
    """CLI entry point for `pyindus chat`."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="pyindus chat",
        description="Interactive TUI for PyIndus",
    )
    parser.add_argument(
        "--session-file",
        default="indus_session.json",
        help="Path to session file (default: indus_session.json)",
    )
    args = parser.parse_args()

    tui = PyIndusTUI(session_file=args.session_file)
    tui.run()


if __name__ == "__main__":
    main()
