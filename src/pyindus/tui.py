"""Interactive TUI chat interface for PyIndus.

Launch with `pyindus chat` for a rich terminal experience.
"""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

LOGO = r"""░█▀█░█░█░▀█▀░█▀█░█▀▄░█░█░█▀▀
░█▀▀░░█░░░█░░█░█░█░█░█░█░▀▀█
░▀░░░░▀░░▀▀▀░▀░▀░▀▀░░▀▀▀░▀▀▀"""

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
FILE_QUERY_RE = re.compile(r"(?:^|\s)@(\S*)$")


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
        try:
            self._run_textual()
        except ImportError:
            self.console.print("[red]Textual is required for the TUI. Please install it.[/red]")
            import sys
            sys.exit(1)

    def _run_textual(self) -> None:
        app = _build_textual_app(self)
        app.run()

    def _prefetch_models(self) -> None:
        """Pre-fetch models so the first /model or chat is fast."""
        try:
            self._models_cache = self.client.get_models()
            if self._models_cache:
                self._current_model_name = self._models_cache[0].name
        except Exception:
            pass

    def _extract_file_refs(self, text: str) -> list[str]:
        """Extract @file references from the input text."""
        return FILE_REF_RE.findall(text)

    def _suggest_files(self, text: str, limit: int = 8) -> list[Path]:
        """Return file completions for the current trailing @query."""
        match = FILE_QUERY_RE.search(text)
        if not match:
            return []

        raw = match.group(1)
        query = raw.strip('"\'')
        base = Path(query).expanduser()
        parent = base.parent if base.parent != Path(".") else Path.cwd()
        prefix = base.name

        if not parent.exists() or not parent.is_dir():
            return []

        matches: list[Path] = []
        try:
            for child in sorted(parent.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                if child.name.startswith(prefix):
                    matches.append(child)
                if len(matches) >= limit:
                    break
        except OSError:
            return []
        return matches


def _looks_like_markdown(text: str) -> bool:
    indicators = ["```", "## ", "- ", "1. ", "**", "__"]
    return any(ind in text for ind in indicators)


def _build_textual_app(tui: PyIndusTUI):
    """Build the full-screen Textual app lazily so tests can run without it."""
    from rich.markdown import Markdown
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.message import Message
    from textual.widgets import Input, Label, ListItem, ListView, RichLog, Static, TextArea, LoadingIndicator
    from textual import events
    from textual.binding import Binding

    class ChatInput(TextArea):
        BINDINGS = [
            Binding("enter", "submit", "Send", priority=True, show=False),
            Binding("shift+enter", "newline", "Newline", priority=True, show=False),
        ]
        def action_submit(self) -> None:
            self.app.action_send()
        def action_newline(self) -> None:
            try:
                self.action_insert_newline()
            except AttributeError:
                row, col = self.cursor_location
                lines = self.text.split("\n")
                if row < len(lines):
                    line = lines[row]
                    lines[row] = line[:col]
                    lines.insert(row + 1, line[col:])
                    self.text = "\n".join(lines)
                    self.cursor_location = (row + 1, 0)

    class FileSuggestion(Message):
        def __init__(self, path: Path) -> None:
            self.path = path
            super().__init__()

    class SessionItem(ListItem):
        def __init__(self, title: str, uid: str, timestamp: str, active: bool = False) -> None:
            marker = "┃" if active else " "
            line = Text(f"{marker} {_ellipsize(title or 'Untitled', 20):<20}{timestamp.rjust(7)}")
            super().__init__(Label(line))
            self.uid = uid
            if active:
                self.add_class("active")

    class GroupItem(ListItem):
        def __init__(self, title: str) -> None:
            super().__init__(Label(title.upper()))

    class CommandSuggestion(Message):
        def __init__(self, cmd: str) -> None:
            self.cmd = cmd
            super().__init__()

    class CommandItem(ListItem):
        def __init__(self, cmd: str, desc: str) -> None:
            super().__init__(Label(f"[bold]{cmd:<10}[/bold] [dim]{desc}[/dim]"))
            self.cmd = cmd

        def on_click(self) -> None:
            self.post_message(CommandSuggestion(self.cmd))

    class SuggestionItem(ListItem):
        def __init__(self, path: Path) -> None:
            label = f"{path.name}/" if path.is_dir() else path.name
            super().__init__(Label(label))
            self.path = path

        def on_click(self) -> None:
            self.post_message(FileSuggestion(self.path))

    class IndusChatApp(App):
        CSS = """
        Screen { background: #121212; color: #FCEDDA; }
        Screen.light { background: #FCEDDA; color: #EE4E34; }

        #root { height: 1fr; }
        
        #sidebar { width: 34; background: #1a1a1a; border-right: solid #EE4E34; padding: 1 1 0 1; }
        Screen.light #sidebar { background: #FCEDDA; }
        #sidebar.hidden { display: none; }
        #logo { color: #EE4E34; height: auto; width: 100%; text-style: bold; margin-bottom: 1; text-align: center; }
        
        #session-search { height: 3; margin: 1 0; border: tall #EE4E34; background: #1a1a1a; }
        Screen.light #session-search { background: #FCEDDA; }
        
        #sessions { height: 1fr; background: transparent; }
        #sessions ListItem { height: 1; padding: 0 1; background: transparent; }
        #sessions ListItem.-disabled { opacity: 1; }
        #sessions ListItem.group { text-style: bold; padding-top: 1; color: #EE4E34; }
        
        #sessions ListItem.active { background: #EE4E34; color: #121212; }
        Screen.light #sessions ListItem.active { color: #FCEDDA; }
        
        #sessions ListItem:hover { background: #33221c; }
        Screen.light #sessions ListItem:hover { background: #EE4E34; color: #FCEDDA; }
        
        #sessions > ListItem.--highlight { background: #EE4E34; color: #121212; }
        Screen.light #sessions > ListItem.--highlight { color: #FCEDDA; }
        
        #main { width: 1fr; background: transparent; }
        
        #status { height: 1; background: transparent; padding: 0 2; text-align: right; }
        
        #chat { height: 1fr; padding: 1 2 0 2; background: transparent; }
        #chat.hidden { display: none; }
        
        #typing { height: auto; max-height: 3; color: #EE4E34; margin: 0 2; background: transparent; }
        #typing.hidden { display: none; }
        
        #welcome { height: 1fr; width: 100%; content-align: center middle; color: #EE4E34; text-style: bold; }
        Screen.light #welcome { color: #EE4E34; }
        #welcome.hidden { display: none; }
        
        #suggestions { height: auto; max-height: 7; margin: 0 2; border: tall #EE4E34; background: #1a1a1a; }
        Screen.light #suggestions { background: #FCEDDA; }
        #suggestions.hidden { display: none; }
        #suggestions ListItem { padding: 0 1; background: transparent; }
        #suggestions > ListItem.--highlight { background: #EE4E34; color: #121212; }
        Screen.light #suggestions > ListItem.--highlight { color: #FCEDDA; }
        
        #input-wrap { height: auto; min-height: 5; max-height: 12; margin: 0 2 1 2; border: tall #EE4E34; background: transparent; }
        #input-hint { height: 1; color: #EE4E34; padding: 0 1; opacity: 0.8; }
        #input { height: auto; min-height: 3; max-height: 10; border: none; background: transparent; }
        
        #footer { height: 1; background: #EE4E34; color: #121212; padding: 0 1; overflow: hidden; }
        Screen.light #footer { color: #FCEDDA; }
        """
        BINDINGS = [
            ("ctrl+b", "toggle_sidebar", "Sidebar"),
            ("ctrl+n", "new_chat", "New"),
            ("ctrl+s", "send", "Send"),
            ("ctrl+d", "delete_session", "Delete"),
            ("ctrl+a", "archive_session", "Archive"),
            ("ctrl+r", "refresh_sessions", "Refresh"),
            ("escape", "clear_suggestions", "Clear"),
            ("ctrl+t", "toggle_theme", "Theme"),
            ("ctrl+q", "quit", "Quit"),
        ]

        def __init__(self, wrapper: PyIndusTUI) -> None:
            super().__init__()
            self.wrapper = wrapper
            self.client = wrapper.client
            self.archived_sessions: set[str] = set()
            self.sessions: list[Any] = []
            self._stream_stop: threading.Event | None = None

        def compose(self) -> ComposeResult:
            with Horizontal(id="root"):
                with Vertical(id="sidebar"):
                    yield Static(LOGO, id="logo")
                    yield Input(placeholder="Search chats", id="session-search")
                    yield ListView(id="sessions")
                with Vertical(id="main"):
                    yield Static("Not authenticated. Use pyindus auth, then reopen chat.", id="status")
                    yield Static(f"{LOGO}\n\nStart typing to begin\nctrl+s send  |  ctrl+b chats  |  @file attach", id="welcome")
                    yield RichLog(id="chat", wrap=True, markup=True, highlight=False, classes="hidden")
                    yield LoadingIndicator(id="typing", classes="hidden")
                    yield ListView(id="suggestions", classes="hidden")
                    with Vertical(id="input-wrap"):
                        yield Static(">  @ for files, / for commands", id="input-hint")
                        yield ChatInput(id="input", language="markdown")
            yield Static(
                "[reverse] ctrl+s [/reverse]  send   [reverse] ctrl+b [/reverse]  sidebar   "
                "[reverse] ctrl+n [/reverse]  new   [reverse] ctrl+d [/reverse]  delete   "
                "[reverse] ctrl+t [/reverse] theme   [reverse] ctrl+q [/reverse] quit",
                id="footer",
            )

        def on_mount(self) -> None:
            self.query_one("#input", ChatInput).focus()
            self.run_worker(self._load_startup, thread=True)

        def _load_startup(self) -> None:
            if not self.client.is_authenticated:
                self.call_from_thread(self._set_status, "Not authenticated. Run `pyindus auth` first.")
                return
            try:
                user = self.client.get_user_info()
                self.call_from_thread(self._set_status, f"Signed in as {user.name or user.sub}")
            except Exception:
                self.call_from_thread(self._set_status, "Signed in")
            self._refresh_sessions_thread()
            try:
                self.wrapper._prefetch_models()
            except Exception:
                pass

        def _write_logo(self) -> None:
            chat = self.query_one("#chat", RichLog)
            chat.write(_welcome_block())

        def _set_status(self, text: str) -> None:
            self.query_one("#status", Static).update(text)

        def _append(self, renderable: Any) -> None:
            self.query_one("#chat", RichLog).write(renderable)

        def action_toggle_sidebar(self) -> None:
            sidebar = self.query_one("#sidebar")
            sidebar.set_class(not sidebar.has_class("hidden"), "hidden")

        def action_toggle_theme(self) -> None:
            self.screen.toggle_class("light")

        def action_refresh_sessions(self) -> None:
            self.run_worker(self._refresh_sessions_thread, thread=True)

        def _refresh_sessions_thread(self) -> None:
            if not self.client.is_authenticated:
                return
            try:
                sessions = [s for s in self.client.list_sessions() if s.uid not in self.archived_sessions]
            except Exception as exc:
                self.call_from_thread(self._set_status, f"Could not load sessions: {exc}")
                return
            self.call_from_thread(self._store_sessions, sessions)

        def _store_sessions(self, sessions) -> None:
            self.sessions = sessions
            self._render_sessions()

        def _render_sessions(self) -> None:
            view = self.query_one("#sessions", ListView)
            view.clear()
            query = self.query_one("#session-search", Input).value.strip().lower()
            grouped: dict[str, list[Any]] = {}
            for session in self.sessions:
                title = session.title or session.uid[:12]
                if query and query not in title.lower():
                    continue
                grouped.setdefault(_date_group(session.created_at), []).append(session)

            for group, sessions in grouped.items():
                if not sessions:
                    continue
                header = GroupItem(group)
                header.add_class("group")
                view.append(header)
                for session in sessions[:40]:
                    title = session.title or session.uid[:12]
                    active = session.uid == self.client._current_session_uid
                    view.append(SessionItem(title, session.uid, _relative_time(session.created_at), active=active))

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id == "session-search":
                self._render_sessions()

        def on_list_view_selected(self, event: ListView.Selected) -> None:
            item = event.item
            if isinstance(item, SessionItem):
                self.client._current_session_uid = item.uid
                self._set_status(f"Session {item.uid}")
                self._render_sessions()
            elif isinstance(item, SuggestionItem):
                self._insert_file_ref(item.path)
            elif isinstance(item, CommandItem):
                self._insert_command(item.cmd)

        def on_file_suggestion(self, event: FileSuggestion) -> None:
            self._insert_file_ref(event.path)

        def on_command_suggestion(self, event: CommandSuggestion) -> None:
            self._insert_command(event.cmd)

        def on_text_area_changed(self, event: TextArea.Changed) -> None:
            if event.text_area.id != "input":
                return
            self._update_suggestions(event.text_area.text)

        def _update_suggestions(self, text: str) -> None:
            view = self.query_one("#suggestions", ListView)
            view.clear()
            
            if text.startswith("/"):
                query = text.lower()
                commands = {
                    "/auth": "Log in with phone number + OTP",
                    "/model": "List and switch AI models",
                    "/session": "Show current session info",
                    "/history": "List recent chat sessions",
                    "/delete": "Delete current session",
                    "/attach": "Attach a file for next message",
                    "/new": "Start a new chat session",
                    "/clear": "Clear the screen",
                    "/help": "Show this help",
                    "/exit": "Exit the TUI",
                }
                matches = [(cmd, desc) for cmd, desc in commands.items() if query in cmd]
                view.set_class(not matches, "hidden")
                for cmd, desc in matches:
                    view.append(CommandItem(cmd, desc))
                return

            suggestions = self.wrapper._suggest_files(text)
            view.set_class(not suggestions, "hidden")
            for path in suggestions:
                view.append(SuggestionItem(path))

        def _insert_file_ref(self, path: Path) -> None:
            editor = self.query_one("#input", ChatInput)
            replacement = f"@{path} "
            editor.text = FILE_QUERY_RE.sub(lambda m: m.group(0)[: -len(m.group(1))] + replacement[1:], editor.text)
            self.action_clear_suggestions()
            editor.focus()

        def _insert_command(self, cmd: str) -> None:
            editor = self.query_one("#input", ChatInput)
            editor.text = cmd + " "
            editor.cursor_location = (0, len(editor.text))
            self.action_clear_suggestions()
            editor.focus()

        def action_clear_suggestions(self) -> None:
            self.query_one("#suggestions", ListView).add_class("hidden")

        def action_new_chat(self) -> None:
            self.client._current_session_uid = None
            self.wrapper._pending_attachments.clear()
            self.query_one("#chat", RichLog).clear()
            self.query_one("#chat").add_class("hidden")
            self.query_one("#welcome").remove_class("hidden")
            self._set_status("New chat")

        def action_archive_session(self) -> None:
            uid = self._selected_session_uid() or self.client._current_session_uid
            if not uid:
                return
            self.archived_sessions.add(uid)
            self._append(Text(f"Archived locally: {uid}", style="#EE4E34"))
            self.action_refresh_sessions()

        def action_delete_session(self) -> None:
            uid = self._selected_session_uid() or self.client._current_session_uid
            if uid:
                self.run_worker(lambda: self._delete_session(uid), thread=True)

        def _selected_session_uid(self) -> str | None:
            item = self.query_one("#sessions", ListView).highlighted_child
            return item.uid if isinstance(item, SessionItem) else None

        def _delete_session(self, uid: str) -> None:
            try:
                self.client.delete_session(uid)
            except Exception as exc:
                self.call_from_thread(self._set_status, f"Delete failed: {exc}")
                return
            self.call_from_thread(self._append, Text(f"Deleted session {uid}", style="#EE4E34"))
            self._refresh_sessions_thread()

        def action_send(self) -> None:
            editor = self.query_one("#input", ChatInput)
            text = editor.text.strip()
            if not text:
                return
            editor.text = ""
            self.action_clear_suggestions()
            
            if text.startswith("/"):
                cmd = text.split()[0].lower()
                if cmd == "/new":
                    self.action_new_chat()
                elif cmd == "/delete":
                    self.action_delete_session()
                elif cmd == "/clear":
                    self.query_one("#chat", RichLog).clear()
                    self.query_one("#welcome").remove_class("hidden")
                    self.query_one("#chat").add_class("hidden")
                elif cmd == "/exit":
                    self.app.exit()
                elif cmd == "/auth":
                    self.query_one("#welcome").add_class("hidden")
                    self.query_one("#chat").remove_class("hidden")
                    self._append(Text("Authentication must be done via CLI. Please exit and run `pyindus auth`.", style="yellow"))
                elif cmd == "/help":
                    self.query_one("#welcome").add_class("hidden")
                    self.query_one("#chat").remove_class("hidden")
                    self._append(Text(HELP_TEXT, style="cyan"))
                elif cmd == "/session":
                    self.query_one("#welcome").add_class("hidden")
                    self.query_one("#chat").remove_class("hidden")
                    auth = self.client.is_authenticated
                    model = self.wrapper._current_model_name
                    self._append(Text(f"Session Info:\nAuthenticated: {auth}\nModel: {model}", style="cyan"))
                elif cmd == "/model":
                    self.query_one("#welcome").add_class("hidden")
                    self.query_one("#chat").remove_class("hidden")
                    self._append(Text(f"Current Model: {self.wrapper._current_model_name}", style="cyan"))
                elif cmd == "/history":
                    self.query_one("#welcome").add_class("hidden")
                    self.query_one("#chat").remove_class("hidden")
                    self._append(Text("History is visible in the sidebar. Press ctrl+b to toggle.", style="cyan"))
                elif cmd == "/attach":
                    self.query_one("#welcome").add_class("hidden")
                    self.query_one("#chat").remove_class("hidden")
                    self._append(Text("Use the @filename syntax to attach files in the TUI (e.g. @src/main.py).", style="cyan"))
                else:
                    self.query_one("#welcome").add_class("hidden")
                    self.query_one("#chat").remove_class("hidden")
                    self._append(Text(f"Unknown command {cmd}. Type /help for available commands.", style="yellow"))
                return
                
            self.query_one("#welcome").add_class("hidden")
            self.query_one("#chat").remove_class("hidden")
            self._append(_message_block("YOU", text))
            self.run_worker(lambda: self._send_message(text), thread=True)

        def _send_message(self, text: str) -> None:
            if not self.client.is_authenticated:
                self.call_from_thread(self._set_status, "Not authenticated. Run `pyindus auth` first.")
                return

            attachments = list(self.wrapper._pending_attachments)
            refs = self.wrapper._extract_file_refs(text)
            prompt = FILE_REF_RE.sub("", text).strip()

            for ref in refs:
                path = Path(ref).expanduser()
                if not path.exists():
                    self.call_from_thread(self._append, Text(f"File not found: {ref}", style="#EE4E34"))
                    return
                self.call_from_thread(self._set_status, f"Uploading {path.name}...")
                try:
                    attachments.append(self.client.upload_attachment(path))
                except Exception as exc:
                    self.call_from_thread(self._append, Text(f"Upload failed for {path}: {exc}", style="#EE4E34"))
                    return

            self.wrapper._pending_attachments.clear()
            if attachments:
                names = ", ".join(a.filename for a in attachments)
                self.call_from_thread(self._append, Text(f"Attached: {names}", style="#EE4E34"))

            try:
                sid = self.client.ensure_session(title=(prompt[:60] or "New Chat"))
            except Exception as exc:
                self.call_from_thread(self._append, Text(f"Could not create session: {exc}", style="#EE4E34"))
                return

            self.call_from_thread(self.query_one("#typing").remove_class, "hidden")

            start = time.monotonic()
            self.call_from_thread(self._set_status, "Indus is responding...")
            try:
                response = self.client.chat(prompt, session_uid=sid, attachments=attachments or None)
            except Exception as exc:
                self.call_from_thread(self.query_one("#typing").add_class, "hidden")
                self.call_from_thread(self._append, Text(f"Chat failed: {exc}", style="#EE4E34"))
                return

            self.call_from_thread(self.query_one("#typing").add_class, "hidden")

            elapsed = time.monotonic() - start
            answer = response.answer or "(no visible answer)"
            self.call_from_thread(self._append, _message_block("INDUS", answer))
            if response.tool_calls:
                tools = ", ".join(tc.name or "tool" for tc in response.tool_calls)
                self.call_from_thread(self._append, Text(f"tools: {tools}", style="#EE4E34"))
            model = self.wrapper._current_model_name or "model"
            self.call_from_thread(self._set_status, f"{model} | {elapsed:.1f}s")
            self._refresh_sessions_thread()

        def _stream_events(self, sid: str, stop: threading.Event) -> None:
            try:
                for event in self.client.stream_session(sid):
                    if stop.is_set():
                        break
                    text = _event_preview(event)
                    if text:
                        self.call_from_thread(self._append, text)
            except Exception:
                return

    return IndusChatApp(tui)


def _welcome_block():
    from rich.align import Align
    from rich.console import Group
    from rich.padding import Padding
    from rich.text import Text

    return Align.center(
        Padding(
            Group(
                Text(LOGO, style="bold", justify="center"),
                Text("", justify="center"),
                Text("Start typing to begin", justify="center"),
                Text("ctrl+s send  |  ctrl+b chats  |  @file attach", justify="center"),
            ),
            (3, 0, 1, 0),
        ),
        vertical="middle",
    )


def _message_block(role: str, content: str):
    from rich.console import Group
    from rich.markdown import Markdown
    from rich.padding import Padding
    from rich.table import Table
    from rich.text import Text

    body = Group(Text(f" {role}", style="#EE4E34 bold"), Padding(Markdown(content), (0, 0, 0, 1)))
    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=2)
    grid.add_column(ratio=1)
    grid.add_row(Text("┃ ", style="#FFA07A"), body)
    return Padding(grid, (0, 0, 1, 0))


def _ellipsize(text: str, width: int) -> str:
    return text if len(text) <= width else f"{text[: max(width - 1, 0)]}…"


def _parse_created_at(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _date_group(value: str) -> str:
    created = _parse_created_at(value)
    if not created:
        return "OLDER"
    now = datetime.now(created.tzinfo or timezone.utc)
    delta_days = (now.date() - created.date()).days
    if delta_days == 0:
        return "TODAY"
    if delta_days == 1:
        return "YESTERDAY"
    return created.strftime("%b %d").upper()


def _relative_time(value: str) -> str:
    created = _parse_created_at(value)
    if not created:
        return ""
    now = datetime.now(created.tzinfo or timezone.utc)
    seconds = max(int((now - created).total_seconds()), 0)
    if seconds < 60:
        return "now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    days = hours // 24
    if days < 7:
        return f"{days}d"
    return created.strftime("%b %-d")


def _event_preview(event: dict) -> str:
    """Best-effort display for Indus SSE events with unknown schema drift."""
    step = event.get("step") if isinstance(event.get("step"), dict) else event
    if not isinstance(step, dict):
        return ""
    if step.get("t") == 17:
        return f"tool {step.get('name', 'tool')}"
    if step.get("t") == 15:
        return "tool result received"
    content = step.get("content")
    if step.get("t") == 20 and content:
        return content.strip()
    event_type = event.get("type") or event.get("event")
    return str(event_type) if event_type else ""


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
