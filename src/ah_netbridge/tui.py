"""Full-screen curses user interface for the managed TaiXin workflows."""

from __future__ import annotations

import curses
import os
import secrets
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .catalog import (
    CLASS_ACTION,
    CLASS_QUERY,
    CLASS_SET,
    CatalogEntry,
    CatalogError,
    command_name,
    load_catalog,
    normalize_command,
    redact_command,
    redact_reply,
)
from .dispatch import (
    CHECK_OK,
    DEFAULT_REPLY_IDLE_MS,
    DEFAULT_REPLY_TIMEOUT_MS,
    SNAPSHOT_CREATED,
    SNAPSHOT_FAILED,
    CheckedCommand,
    check_command,
    reply_is_device_error,
    snapshot_before_write,
)
from .native import (
    BANDWIDTHS_MHZ,
    CAP_CREDENTIALS,
    CAP_RADIO,
    CHANNEL_MAX_KHZ,
    CHANNEL_MIN_KHZ,
    FIELD_PSK,
    MAX_CHANNELS,
    STAGE_PROBE,
    STATUS_NOT_FOUND,
    STATUS_TIMEOUT,
    STATUS_UNSUPPORTED,
    TX_POWER_MAX_DBM,
    TX_POWER_MIN_DBM,
    Capabilities,
    ManagedConfig,
    NativeError,
    Netbridge,
    c_text,
    capability_text,
    status_name,
    valid_channel_khz,
)
from .network import DeviceInfo, InterfaceInfo
from .presets import PresetError, RadioPreset, load_presets
from .storage import (
    SSID_MAX_BYTES,
    StorageError,
    create_saved_configuration,
    create_snapshot,
    list_saved_configurations,
    load_shared_psk,
    load_snapshot,
    psk_preview,
    shared_psk_exists,
    shared_psk_path,
    snapshot_path,
    write_shared_psk,
)

# Menu results other than a selected item index.
MENU_BACK = -1
MENU_QUIT = -2
# Helper result next to MENU_BACK/MENU_QUIT: a value was chosen.
PICK_DONE = 0

KEY_ESCAPE = 27
KEY_TAB = 9
KEY_LINE_FEED = 10
KEY_CARRIAGE_RETURN = 13
ESC_DELAY_MS = 25

MIN_HEIGHT = 10
MIN_WIDTH = 76
STATUS_WIDTH = 31
LEFT_MARGIN = 2
TITLE_ROW = 0
UPPER_INDICATOR_ROW = 1
BODY_TOP = 2
FRAME_FIXED_ROWS = 4  # title, upper indicator, lower indicator, key hint
STATUS_TOP = 2
ELLIPSIS = "…"
# Body text keeps up to a third of the free rows even beside a long menu.
BODY_SHARE_DIVISOR = 3

CONFIRM_NO = 0
CONFIRM_YES = 1

MAIN_CREDENTIALS = 0
MAIN_RADIO = 1
MAIN_BACKUP = 2
MAIN_APPLY_SAVED = 3
MAIN_RESTORE_SNAPSHOT = 4
MAIN_MANUAL_AT = 5

CRED_SSID_AND_PSK = 0
CRED_SSID_ONLY = 1
CRED_PSK_ONLY = 2
CRED_COPY_DEVICE_PSK = 3

PSK_GENERATE = 0
PSK_USE_FILE = 1

RADIO_MANUAL = 0
RADIO_PRESET = 1

MANUAL_CHANNELS = 0
MANUAL_BANDWIDTH = 1
MANUAL_TX_POWER = 2
MANUAL_REVIEW = 3

CHANNEL_MODE_STANDARD = 0
CHANNEL_MODE_TOGGLE = 1

TOGGLE_DONE = 0

FAILURE_RETRY = 0
FAILURE_IGNORE = 1
FAILURE_RESTORE = 2

WRITE_CREDENTIALS = 1
WRITE_PSK = 2
WRITE_RADIO = 3
WRITE_RESTORE = 4
WRITE_SSID = 5

# run_action results.
ACTION_VERIFIED = 0
ACTION_ABANDONED = 1
ACTION_PSK_UNREADABLE = 2

TARGET_READY = 0
TARGET_QUIT = 1

CONFIG_NAME_MAX = 64

# Line editor (UI.edit_line) results and control keys.
LINE_ACCEPT = 0
LINE_CANCEL = 1
LINE_EDITOR = 2
CTRL_A = "\x01"
CTRL_E = "\x05"
CTRL_G = "\x07"
CTRL_K = "\x0b"
CTRL_U = "\x15"
CTRL_W = "\x17"
KEY_DELETE_CHARACTER = "\x7f"
KEY_BACKSPACE_CHARACTER = "\b"

# Catalogue picker (UI.pick) results besides PICK_DONE / MENU_BACK / MENU_QUIT.
PICK_FREE = 1
PICK_EDITOR = 2
FREE_COMMAND_KEY = ":"
TYPEAHEAD_WINDOW_SECONDS = 0.8

# Manual AT command screens.
CATALOG_FREE_ROW = 0
AT_REPLY_SEND_AGAIN = 0
AT_REPLY_EDIT = 1
AT_REPLY_CATALOG = 2
BATCH_SEND = 0
BATCH_EDIT = 1
BATCH_CATALOG = 2
RESULT_CATALOG = 0
RESULT_EDIT = 1
AT_COMMAND_MAX = 1024
AT_HISTORY_MAX = 50
AT_NAME_WIDTH = 15
AT_CLASS_WIDTH = 6
SEND_ALL_WORD = "SEND"
EDITOR_FALLBACKS = ("vim", "vi")
EDITOR_UNAVAILABLE = -1
# ^G results: the edited payload is one line, a reviewed batch, or unchanged.
PAYLOAD_LINE = 0
PAYLOAD_BATCH = 1
PAYLOAD_UNCHANGED = 2
MILLISECONDS_PER_SECOND = 1000
SET_PLACEHOLDER = "<"
FREE_ROW_BODY = (
    "Type any AT command, or press a letter to jump to catalogue commands starting with "
    "it. ^G edits the command in your $EDITOR; several lines there make a batch."
)
ACTION_COMMAND_WARNING = (
    "Action commands can reboot the device, restore factory defaults, start pairing, "
    "upgrade firmware, sleep the radio or run RF test modes."
)
UNKNOWN_COMMAND_WARNING = "This command is not classified by the catalogue; its effect is unknown."
DEFAULT_BANDWIDTH_MHZ = 1
DEFAULT_TX_POWER_DBM = 14

MANUAL_CHANNEL_OPTIONS_KHZ = tuple(range(863_000, 868_001, 100))
TX_POWER_OPTIONS_DBM = tuple(range(TX_POWER_MIN_DBM, TX_POWER_MAX_DBM + 1))
KHZ_PER_MHZ = 1000
# (region tag, channel centres in kHz, bandwidth in MHz). These mirror the bundled
# presets in src/ah_netbridge/presets/; keep the two in step. Labels are built by
# standard_set_label().
STANDARD_CHANNEL_SETS: tuple[tuple[str, tuple[int, ...], int], ...] = (
    ("CE IoT", (863500, 864500, 865500, 866500, 867500), 1),
    ("CE IoT", (864000, 866000), 2),
    ("CE A/V", (865500, 866500, 867500), 1),
    ("CE A/V", (866000,), 2),
    ("FCC US", (908000, 916000, 924000), 8),
    ("FCC US", (906000, 910000, 914000, 918000, 922000, 926000), 4),
    ("FCC US", tuple(range(905000, 925001, 2000)), 2),
    ("MIC no-duty", (922000,), 2),
    ("MIC no-duty", (921500, 922500), 1),
    ("MIC duty", (924000,), 4),
    ("MIC duty", (922000, 924000, 926000), 2),
    ("MIC duty", tuple(range(921500, 926501, 1000)), 1),
)
STANDARD_SETS_HELP = (
    "Rows show bandwidth, channel span and region. MIC duty is Japan's duty-limited "
    "class; MIC no-duty is its no-duty-limit class."
)

MANUAL_RADIO_WARNING = (
    "You are responsible for frequency, bandwidth, power, licensing and duty-cycle "
    "compliance in the operating jurisdiction."
)
PEER_PAIRING_HINT = (
    "Anjielo’s physical S1 buttons may need to be pressed simultaneously to refresh "
    "proprietary peer-pairing state."
)
ANOTHER_DEVICE_HINT = (
    "To configure another device, press Esc at the main menu to return to device selection."
)


@dataclass(frozen=True)
class MenuItem:
    label: str
    enabled: bool = True


@dataclass
class Frame:
    """Geometry of one drawn screen; the reserved rows hold a menu or an input field."""

    height: int
    text_width: int
    body_rows: int
    body_line_count: int
    body_scroll: int
    reserved_top: int
    reserved_rows: int


@dataclass
class WriteRequest:
    kind: int
    mac: bytes
    ssid: str = ""
    psk: str = ""
    channels_khz: tuple[int, ...] = ()
    bandwidth_mhz: int = 0
    tx_power_dbm: int = 0
    config: ManagedConfig | None = None


def index_of(values: Sequence[int], value: int) -> int:
    """Position of value in values, or 0 when it is not there."""

    for index in range(len(values)):
        if values[index] == value:
            return index
    return 0


def mac_text(mac: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in mac)


def clamp(value: int, low: int, high: int) -> int:
    if value < low:
        return low
    if value > high:
        return high
    return value


def mhz_text(khz: int) -> str:
    if khz % KHZ_PER_MHZ == 0:
        return str(khz // KHZ_PER_MHZ)
    return f"{khz / KHZ_PER_MHZ:.1f}"


def standard_set_label(tag: str, channels: Sequence[int], bandwidth: int) -> str:
    """Bandwidth first, so a clipped row never hides the value the choice applies."""

    span = mhz_text(channels[0])
    if len(channels) > 1:
        span += "–" + mhz_text(channels[-1])
    return f"{bandwidth} MHz · {span} MHz · {tag}"


def clip_label(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[:width - 1] + ELLIPSIS


def wrap_body(body: str, width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in body.splitlines():
        wrapped = textwrap.wrap(paragraph, width=width)
        if not wrapped:
            lines.append("")
            continue
        lines.extend(wrapped)
    return lines


class UI:
    def __init__(self, window: "curses._CursesWindow"):
        self.window = window
        self.status_lines = ["No device selected."]
        self.title_prefix = "AH Netbridge"
        self.window.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        try:
            curses.set_escdelay(ESC_DELAY_MS)
        except curses.error:
            pass

    def set_status(self, lines: Sequence[str]) -> None:
        self.status_lines = list(lines)
        if not self.status_lines:
            self.status_lines = ["State unavailable."]

    def _put(self, row: int, col: int, text: str, limit: int, attr: int = 0) -> None:
        """Draw text clipped to the window; never touch the last column."""

        height, width = self.window.getmaxyx()
        if row < 0 or row >= height or col < 0 or col >= width - 1:
            return
        count = min(limit, width - 1 - col, len(text))
        if count <= 0:
            return
        try:
            self.window.addnstr(row, col, text, count, attr)
        except curses.error:
            return

    def _draw_status(self, height: int, status_x: int, status_width: int) -> None:
        """Drop blank separators first, then mark cut lines with a final ellipsis row."""

        self._put(TITLE_ROW, status_x, "Current setup", status_width, curses.A_BOLD)
        rows = height - 1 - STATUS_TOP
        if rows < 1:
            return
        lines: list[str] = []
        for item in self.status_lines:
            wrapped = textwrap.wrap(item, width=max(8, status_width))
            if not wrapped:
                lines.append("")
                continue
            lines.extend(wrapped)
        if len(lines) > rows:
            compact: list[str] = []
            for line in lines:
                if line:
                    compact.append(line)
            lines = compact
        if len(lines) > rows:
            lines = lines[:rows - 1] + [ELLIPSIS]
        for index in range(len(lines)):
            self._put(STATUS_TOP + index, status_x, lines[index], status_width)

    def _frame(self, title: str, body: str, scroll: int, reserved: int,
               scrollable: bool = True) -> Frame | None:
        """Draw the title, status panel and body; a body that is not scrollable is
        cut with an ellipsis instead of PgUp/PgDn hints."""

        self.window.erase()
        height, width = self.window.getmaxyx()
        if height < MIN_HEIGHT or width < MIN_WIDTH:
            message = f"Terminal too small (minimum {MIN_WIDTH}×{MIN_HEIGHT}). Resize to continue."
            self._put(0, 0, message, width)
            self.window.refresh()
            return None
        divider = width - STATUS_WIDTH - 1
        text_width = divider - 2 * LEFT_MARGIN
        for row in range(height):
            self._put(row, divider, "│", 1, curses.A_DIM)
        status_x = divider + 2
        self._draw_status(height, status_x, width - status_x - 1)
        self._put(TITLE_ROW, LEFT_MARGIN, self.title_prefix + " — " + title, text_width,
                  curses.A_BOLD)

        lines = wrap_body(body, text_width)
        area = height - FRAME_FIXED_ROWS
        minimum_body = 0
        if lines:
            minimum_body = min(len(lines), max(1, area // BODY_SHARE_DIVISOR))
        reserved_rows = min(reserved, area - minimum_body)
        body_rows = min(len(lines), area - reserved_rows)
        max_scroll = len(lines) - body_rows
        scroll = clamp(scroll, 0, max_scroll)
        if scroll > 0:
            self._put(UPPER_INDICATOR_ROW, LEFT_MARGIN, "↑ more (PgUp)", text_width, curses.A_DIM)
        for index in range(body_rows):
            line = lines[scroll + index]
            if not scrollable and index == body_rows - 1 and scroll < max_scroll:
                line = clip_label(line + " " + ELLIPSIS, text_width)
            self._put(BODY_TOP + index, LEFT_MARGIN, line, text_width)
        lower_row = BODY_TOP + body_rows
        if scrollable and scroll < max_scroll:
            self._put(lower_row, LEFT_MARGIN, "more ↓ (PgDn)", text_width, curses.A_DIM)
        return Frame(height, text_width, body_rows, len(lines), scroll, lower_row + 1,
                     reserved_rows)

    def _scroll_key(self, key: int, frame: Frame) -> int:
        """Return the new body scroll offset for a scroll key, or -1 if not a scroll key."""

        page = max(1, frame.body_rows - 1)
        if key == curses.KEY_NPAGE:
            return frame.body_scroll + page
        if key == curses.KEY_PPAGE:
            return max(0, frame.body_scroll - page)
        if key == curses.KEY_HOME:
            return 0
        if key == curses.KEY_END:
            return frame.body_line_count
        return -1

    def menu(self, title: str, items: Sequence[MenuItem], body: str = "",
             allow_cancel: bool = True, initial: int = 0, dialog: bool = False) -> int:
        """Return the chosen item index, MENU_BACK or MENU_QUIT.

        A dialog (confirm/message) has no Back/Quit rows and ignores 'q'; Esc cancels it."""

        entries = list(items)
        back_index = -1
        quit_index = -1
        if not dialog:
            entries.append(MenuItem("", False))
            if allow_cancel:
                back_index = len(entries)
                entries.append(MenuItem("<- Back"))
            quit_index = len(entries)
            entries.append(MenuItem("Quit utility"))
        selected = initial
        if selected < 0 or selected >= len(entries):
            selected = 0
        if not entries[selected].enabled:
            selected = self._step(entries, selected, 1)
        offset = 0
        scroll = 0
        hint = "↑/↓ select · Enter choose"
        if dialog and len(items) == 1:
            hint = "Enter continue"
        elif allow_cancel and dialog:
            hint += " · Esc cancel"
        elif allow_cancel:
            hint += " · Esc back"
        while True:
            frame = self._frame(title, body, scroll, len(entries))
            if frame is None:
                self.window.getch()
                continue
            scroll = frame.body_scroll
            visible = max(1, frame.reserved_rows)
            if selected < offset:
                offset = selected
            elif selected >= offset + visible:
                offset = selected - visible + 1
            for row in range(visible):
                index = offset + row
                if index >= len(entries):
                    break
                item = entries[index]
                if not item.label:
                    continue
                marker = "  "
                style = 0
                if index == selected:
                    marker = "› "
                    style = curses.A_REVERSE
                elif not item.enabled:
                    style = curses.A_DIM
                suffix = ""
                if not item.enabled:
                    suffix = " (unavailable)"
                text = clip_label(marker + item.label + suffix, frame.text_width)
                self._put(frame.reserved_top + row, LEFT_MARGIN, text, frame.text_width, style)
            self._put(frame.height - 1, LEFT_MARGIN, hint, frame.text_width, curses.A_DIM)
            self.window.refresh()
            key = self.window.getch()
            if key == curses.KEY_RESIZE:
                continue
            new_scroll = self._scroll_key(key, frame)
            if new_scroll >= 0:
                # Page keys scroll text that does not fit; otherwise they page the menu.
                if frame.body_line_count > frame.body_rows:
                    scroll = new_scroll
                else:
                    selected = self._page(entries, selected, key, visible)
                continue
            if key == ord("q"):
                if dialog:
                    continue
                return MENU_QUIT
            if key == KEY_ESCAPE:
                if allow_cancel:
                    return MENU_BACK
                continue
            if key == curses.KEY_UP or key == ord("k"):
                selected = self._step(entries, selected, -1)
            elif key == curses.KEY_DOWN or key == ord("j") or key == KEY_TAB:
                selected = self._step(entries, selected, 1)
            elif key in (KEY_LINE_FEED, KEY_CARRIAGE_RETURN, curses.KEY_ENTER):
                if not entries[selected].enabled:
                    continue
                if selected == back_index:
                    return MENU_BACK
                if selected == quit_index:
                    return MENU_QUIT
                return selected

    def _step(self, entries: list[MenuItem], selected: int, direction: int) -> int:
        index = selected
        for _ in range(len(entries)):
            index = (index + direction) % len(entries)
            if entries[index].enabled:
                return index
        return selected

    def _page(self, entries: list[MenuItem], selected: int, key: int, rows: int) -> int:
        """Move by one visible page (PgUp/PgDn) or to an end (Home/End), skipping disabled rows."""

        last = len(entries) - 1
        target = last
        direction = -1
        if key == curses.KEY_NPAGE:
            target = selected + rows
            direction = 1
        elif key == curses.KEY_PPAGE:
            target = selected - rows
        elif key == curses.KEY_HOME:
            target = 0
            direction = 1
        target = clamp(target, 0, last)
        index = target
        while 0 <= index <= last:
            if entries[index].enabled:
                return index
            index += direction
        index = target
        while 0 <= index <= last:
            if entries[index].enabled:
                return index
            index -= direction
        return selected

    def message(self, title: str, body: str) -> None:
        self.menu(title, [MenuItem("Continue")], body, dialog=True)

    def success_message(self, title: str, body: str) -> None:
        self.menu(title, [MenuItem("Continue setup")], body, dialog=True)

    def progress(self, title: str, body: str) -> None:
        self._frame(title, body, 0, 0)
        self.window.refresh()

    def confirm(self, title: str, body: str) -> bool:
        choice = self.menu(title, [MenuItem("No"), MenuItem("Yes")], body, dialog=True)
        return choice == CONFIRM_YES

    def input(self, title: str, prompt: str, *, maximum: int = 256) -> str | None:
        """Return the entered text, or None when the user pressed Esc."""

        value = ""
        scroll = 0
        while True:
            frame = self._frame(title, prompt, scroll, 1)
            if frame is None:
                self.window.getch()
                continue
            scroll = frame.body_scroll
            shown = value
            visible = frame.text_width - 1
            if len(shown) > visible:
                shown = shown[len(shown) - visible:]
            self._put(frame.reserved_top, LEFT_MARGIN, shown + " ", frame.text_width,
                      curses.A_REVERSE)
            self._put(frame.height - 1, LEFT_MARGIN, "Enter accept · Esc cancel",
                      frame.text_width, curses.A_DIM)
            self.window.refresh()
            key = self.window.get_wch()
            if key == curses.KEY_RESIZE:
                continue
            if isinstance(key, int):
                new_scroll = self._scroll_key(key, frame)
                if new_scroll >= 0:
                    scroll = new_scroll
                    continue
                if key == curses.KEY_ENTER:
                    return value
                if key == curses.KEY_BACKSPACE:
                    value = value[:-1]
                continue
            if key == "\x1b":
                return None
            if key == "\n" or key == "\r":
                return value
            if key == "\b" or key == "\x7f":
                value = value[:-1]
            elif key.isprintable() and len(value) < maximum:
                value += key

    def edit_line(self, title: str, prompt: str, initial: str, history: Sequence[str],
                  *, maximum: int = AT_COMMAND_MAX) -> tuple[int, str]:
        """Edit one line with a cursor; return (LINE_ACCEPT|LINE_CANCEL|LINE_EDITOR, text).

        Keys: ←/→, Home/^A, End/^E, Backspace, Delete, ^U/^K kill to start/end,
        ^W delete word, ↑/↓ history, ^G open $EDITOR, Enter send, Esc cancel."""

        value = initial[:maximum]
        cursor = len(value)
        recall = len(history)
        draft = value
        scroll = 0
        hint = "Enter send · ↑↓ hist · ^G editor · Esc"
        while True:
            frame = self._frame(title, prompt, scroll, 1)
            if frame is None:
                self.window.getch()
                continue
            scroll = frame.body_scroll
            visible = frame.text_width - 1
            start = 0
            if cursor > visible:
                start = cursor - visible
            shown = value[start:start + visible]
            self._put(frame.reserved_top, LEFT_MARGIN, shown + " ", frame.text_width,
                      curses.A_REVERSE)
            cursor_text = " "
            if cursor < len(value):
                cursor_text = value[cursor]
            self._put(frame.reserved_top, LEFT_MARGIN + cursor - start, cursor_text, 1,
                      curses.A_BOLD | curses.A_UNDERLINE)
            self._put(frame.height - 1, LEFT_MARGIN, hint, frame.text_width, curses.A_DIM)
            self.window.refresh()
            key = self.window.get_wch()
            if key == curses.KEY_RESIZE:
                continue
            if isinstance(key, int):
                if key == curses.KEY_ENTER:
                    return LINE_ACCEPT, value
                if key == curses.KEY_LEFT:
                    cursor = max(0, cursor - 1)
                elif key == curses.KEY_RIGHT:
                    cursor = min(len(value), cursor + 1)
                elif key == curses.KEY_HOME:
                    cursor = 0
                elif key == curses.KEY_END:
                    cursor = len(value)
                elif key == curses.KEY_BACKSPACE:
                    if cursor > 0:
                        value = value[:cursor - 1] + value[cursor:]
                        cursor -= 1
                elif key == curses.KEY_DC:
                    value = value[:cursor] + value[cursor + 1:]
                elif key == curses.KEY_UP:
                    if recall == len(history):
                        draft = value
                    if recall > 0:
                        recall -= 1
                        value = history[recall]
                        cursor = len(value)
                elif key == curses.KEY_DOWN:
                    if recall < len(history):
                        recall += 1
                        value = draft
                        if recall < len(history):
                            value = history[recall]
                        cursor = len(value)
                elif key == curses.KEY_NPAGE or key == curses.KEY_PPAGE:
                    scroll = self._scroll_key(key, frame)
                continue
            if key == "\x1b":
                return LINE_CANCEL, value
            if key == "\n" or key == "\r":
                return LINE_ACCEPT, value
            if key == CTRL_G:
                return LINE_EDITOR, value
            if key == KEY_BACKSPACE_CHARACTER or key == KEY_DELETE_CHARACTER:
                if cursor > 0:
                    value = value[:cursor - 1] + value[cursor:]
                    cursor -= 1
            elif key == CTRL_A:
                cursor = 0
            elif key == CTRL_E:
                cursor = len(value)
            elif key == CTRL_U:
                value = value[cursor:]
                cursor = 0
            elif key == CTRL_K:
                value = value[:cursor]
            elif key == CTRL_W:
                start = cursor
                while start > 0 and value[start - 1] == " ":
                    start -= 1
                while start > 0 and value[start - 1] not in " =,":
                    start -= 1
                value = value[:start] + value[cursor:]
                cursor = start
            elif key.isprintable() and len(value) < maximum:
                value = value[:cursor] + key + value[cursor:]
                cursor += 1

    def pick(self, title: str, items: Sequence[MenuItem], names: Sequence[str],
             bodies: Sequence[str], initial: int = 0) -> tuple[int, int]:
        """Catalogue list with type-to-jump; return (code, index).

        code is PICK_DONE (Enter on index), PICK_FREE (':'), PICK_EDITOR (^G),
        MENU_BACK (Esc) or MENU_QUIT. names[i] is matched by typed letters; an empty
        name is never a jump target. Letters jump instead of moving or quitting."""

        entries = list(items)
        selected = clamp(initial, 0, len(entries) - 1)
        offset = 0
        typed = ""
        typed_at = 0.0
        hint = "a–z jump · Enter · : type · ^G editor"
        while True:
            # PgUp/PgDn page the list here, so the preview is not scrollable.
            frame = self._frame(title, bodies[selected], 0, len(entries), scrollable=False)
            if frame is None:
                self.window.getch()
                continue
            visible = max(1, frame.reserved_rows)
            if selected < offset:
                offset = selected
            elif selected >= offset + visible:
                offset = selected - visible + 1
            for row in range(visible):
                index = offset + row
                if index >= len(entries):
                    break
                marker = "  "
                style = 0
                if index == selected:
                    marker = "› "
                    style = curses.A_REVERSE
                text = clip_label(marker + entries[index].label, frame.text_width)
                self._put(frame.reserved_top + row, LEFT_MARGIN, text, frame.text_width, style)
            self._put(frame.height - 1, LEFT_MARGIN, hint, frame.text_width, curses.A_DIM)
            self.window.refresh()
            key = self.window.get_wch()
            if key == curses.KEY_RESIZE:
                continue
            if isinstance(key, int):
                if key == curses.KEY_ENTER:
                    return PICK_DONE, selected
                if key == curses.KEY_UP:
                    selected = self._step(entries, selected, -1)
                elif key == curses.KEY_DOWN:
                    selected = self._step(entries, selected, 1)
                elif key in (curses.KEY_NPAGE, curses.KEY_PPAGE, curses.KEY_HOME, curses.KEY_END):
                    selected = self._page(entries, selected, key, visible)
                typed = ""
                continue
            if key == "\x1b":
                return MENU_BACK, selected
            if key == "\n" or key == "\r":
                return PICK_DONE, selected
            if key == "\t":
                selected = self._step(entries, selected, 1)
                continue
            if key == FREE_COMMAND_KEY:
                return PICK_FREE, selected
            if key == CTRL_G:
                return PICK_EDITOR, selected
            if not (key.isascii() and (key.isalnum() or key == "_")):
                continue
            now = self.clock()
            letter = key.upper()
            if typed and now - typed_at <= TYPEAHEAD_WINDOW_SECONDS:
                typed += letter
            else:
                typed = letter
            typed_at = now
            selected = typeahead_target(names, selected, typed)

    def clock(self) -> float:
        return time.monotonic()

    def run_external(self, argv: Sequence[str], directory: str) -> int:
        """Leave curses, run a program in `directory` on the real terminal, come back;
        return its exit code."""

        curses.def_prog_mode()
        curses.endwin()
        try:
            completed = subprocess.run(list(argv), cwd=directory, check=False)
            code = completed.returncode
        except OSError:
            code = EDITOR_UNAVAILABLE
        finally:
            curses.reset_prog_mode()
            self.window.refresh()
        return code


def first_match(names: Sequence[str], prefix: str) -> int:
    for index in range(len(names)):
        if names[index] and names[index].startswith(prefix):
            return index
    return -1


def next_match(names: Sequence[str], selected: int, prefix: str) -> int:
    """The next name with this prefix after `selected`, wrapping around; -1 if none."""

    count = len(names)
    for step in range(1, count + 1):
        index = (selected + step) % count
        if names[index] and names[index].startswith(prefix):
            return index
    return -1


def typeahead_target(names: Sequence[str], selected: int, typed: str) -> int:
    """Row for the typed letters.

    One letter: the first name starting with it, or the next one when the current
    row already starts with it (so pressing T repeatedly walks the T commands).
    Several letters: the first name with that prefix; a repeated letter with no
    such prefix ("TT") keeps walking that letter's commands."""

    if not typed:
        return selected
    letter = typed[0]
    current_matches = 0 <= selected < len(names) and names[selected].startswith(letter)
    if len(typed) == 1:
        if current_matches:
            target = next_match(names, selected, letter)
        else:
            target = first_match(names, letter)
    else:
        target = first_match(names, typed)
        if target < 0 and typed == letter * len(typed):
            target = next_match(names, selected, letter)
    if target < 0:
        return selected
    return target


def parse_ssid(value: str) -> str:
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= SSID_MAX_BYTES or "\0" in value or "\n" in value or "\r" in value:
        raise ValueError("SSID must contain 1–32 UTF-8 bytes without NUL or newlines.")
    return value


def generate_psk() -> str:
    return secrets.token_bytes(32).hex()


def format_channels(channels: Sequence[int]) -> str:
    return ", ".join(f"{value / 1000:.1f}" for value in channels)


def config_channels(config: ManagedConfig) -> tuple[int, ...]:
    count = min(config.channel_count, MAX_CHANNELS)
    return tuple(config.channels_khz[index] for index in range(count))


def tx_power_text(config: ManagedConfig) -> str:
    """The saved setting, plus the live value when the firmware runs at another power."""

    text = f"{config.stored_tx_power_dbm} dBm"
    if config.runtime_tx_power_dbm != config.stored_tx_power_dbm:
        text += f" (live {config.runtime_tx_power_dbm})"
    return text


def config_summary(config: ManagedConfig) -> str:
    """Human summary of a full configuration; never includes the PSK."""

    return (
        f"SSID: {c_text(config.ssid)}\nPSK: protected\n"
        f"Security: {c_text(config.encryption)}\n"
        f"Channels: {format_channels(config_channels(config))} MHz\n"
        f"Bandwidth: {config.bandwidth_mhz} MHz\n"
        f"TX power: {tx_power_text(config)}"
    )


def radio_confirm_body(mac_text: str, channels: Sequence[int], bandwidth: int, power: int,
                       preset: RadioPreset | None) -> str:
    warning = MANUAL_RADIO_WARNING
    if preset is not None:
        warning = preset.warning
    summary = (
        f"MAC: {mac_text}\nChannels: {format_channels(channels)} MHz\n"
        f"Bandwidth: {bandwidth} MHz\nTX power: {power} dBm"
    )
    if preset is not None:
        summary += f"\nPreset: {preset.name} ({preset.jurisdiction})\nSource: {preset.source_url}"
    return warning + "\n\n" + summary + "\n\nApply and verify every field?"


def perform_write(backend: Netbridge, request: WriteRequest) -> None:
    if request.kind == WRITE_CREDENTIALS:
        backend.apply_credentials(request.mac, request.ssid, request.psk)
        return
    if request.kind == WRITE_SSID:
        backend.apply_ssid(request.mac, request.ssid)
        return
    if request.kind == WRITE_PSK:
        backend.apply_psk(request.mac, request.psk)
        return
    if request.kind == WRITE_RADIO:
        backend.apply_radio(request.mac, request.channels_khz, request.bandwidth_mhz,
                            request.tx_power_dbm)
        return
    if request.kind == WRITE_RESTORE:
        if request.config is None:
            raise ValueError("No configuration to restore.")
        backend.restore(request.mac, request.config)
        return
    raise ValueError(f"Unknown write request {request.kind}.")


def psk_snapshot_failed(error: Exception) -> bool:
    """True for apply_ssid's "device PSK unreadable, nothing written" failure."""

    if not isinstance(error, NativeError) or error.result is None:
        return False
    result = error.result
    if error.status != STATUS_UNSUPPORTED or result.applied_mask != 0:
        return False
    return result.failed_stage == STAGE_PROBE and result.failed_field == FIELD_PSK


def catalog_in_name_order(catalog: Sequence[CatalogEntry]) -> list[CatalogEntry]:
    by_name: dict[str, CatalogEntry] = {}
    for entry in catalog:
        by_name[entry.name] = entry
    ordered: list[CatalogEntry] = []
    for name in sorted(by_name):
        ordered.append(by_name[name])
    return ordered


def catalog_row_label(entry: CatalogEntry) -> str:
    return f"{entry.name:<{AT_NAME_WIDTH}} {entry.safety:<{AT_CLASS_WIDTH}} {entry.summary}"


def catalog_entry_body(entry: CatalogEntry) -> str:
    """The highlighted command's preview: forms first, then facts, then the summary."""

    forms: list[str] = []
    if entry.query:
        forms.append("Query: " + ", ".join(entry.query))
    if entry.set:
        set_text = "Set: " + entry.set
        if entry.args:
            set_text += f" ({entry.args})"
        forms.append(set_text)
    facts = f"{entry.safety} · persists: {entry.persists} · {entry.confidence} confidence"
    if entry.sensitive:
        facts += " · reply holds a secret (hidden)"
    return " · ".join(forms) + "\n" + facts + "\n" + entry.summary


def initial_draft(entry: CatalogEntry) -> str:
    """The line to start editing from: the query form, else the set form up to its argument."""

    if entry.query:
        return entry.query[0]
    placeholder = entry.set.find(SET_PLACEHOLDER)
    if placeholder < 0:
        return entry.set
    return entry.set[:placeholder]


def entry_about(entry: CatalogEntry | None) -> str:
    if entry is None:
        return "Not in the catalogue."
    return f"{entry.name}: {entry.summary} (persists: {entry.persists})"


def reply_report(checked: CheckedCommand, status: int, text: str, elapsed_ms: int,
                 note: str) -> str:
    """Redacted reply text for one sent command."""

    verdict = status_name(status)
    if status == STATUS_TIMEOUT:
        verdict += " — no reply"
    elif reply_is_device_error(text):
        verdict += " — the device rejected the command"
    lines = [
        f"Command: {redact_command(checked.text)}  [{checked.command_class}]",
        f"Status: {verdict} · {elapsed_ms} ms",
    ]
    if note:
        lines.append(note)
    lines.append("")
    reply = redact_reply(text).replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    lines.append(reply or "(no reply)")
    return "\n".join(lines)


def editor_command() -> list[str]:
    """$VISUAL, then $EDITOR (split like a shell would), then vim, then vi."""

    for variable in ("VISUAL", "EDITOR"):
        value = os.environ.get(variable, "").strip()
        if value:
            try:
                words = shlex.split(value)
            except ValueError:
                continue
            if words:
                return words
    for name in EDITOR_FALLBACKS:
        found = shutil.which(name)
        if found:
            return [found]
    return []


def batch_lines(text: str) -> list[str]:
    commands: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        commands.append(stripped)
    return commands


class Application:
    def __init__(self, ui: UI, backend: Netbridge, data_root: Path, preset_directory: Path,
                 *, interface_name: str | None = None, mac: bytes | None = None):
        self.ui = ui
        self.backend = backend
        self.data_root = data_root
        self.preset_directory = preset_directory
        self.preselected_interface = interface_name
        self.preselected_mac = mac
        self.interface: InterfaceInfo | None = None
        self.device: DeviceInfo | None = None
        self.capabilities: Capabilities | None = None
        self.snapshot: ManagedConfig | None = None
        self.snapshot_state = "none"
        self.quit_requested = False
        self.session_wrote = False
        self.write_incomplete = False
        self.last_write_partial = False
        self.catalog: list[CatalogEntry] | None = None
        self.at_history: list[str] = []
        self.manual_snapshot_checked = False
        self.status_values = ["No device selected."]
        self._publish_status()

    # -- status panel -------------------------------------------------------

    def _publish_status(self, note: str = "") -> None:
        lines = list(self.status_values)
        if note:
            lines.extend(["", note])
        lines.extend(["", f"Data: {self.data_root}"])
        self.ui.set_status(lines)

    def _target_lines(self) -> list[str]:
        lines: list[str] = []
        if self.device is not None:
            lines.append(f"MAC: {self.device.mac_text}")
        if self.interface is not None:
            lines.append(f"Interface: {self.interface.name} ({self.interface.address})")
        return lines

    def refresh_status(self, note: str = "") -> None:
        """Managed values first, identity after: a short panel keeps what matters."""

        if self.device is None or self.capabilities is None:
            lines = self._target_lines()
            if self.device is not None:
                lines.extend(["", "Current values pending compatibility probe."])
            if not lines:
                lines.append("No device selected.")
            self.status_values = lines
            self._publish_status(note)
            return
        probe_role = c_text(self.capabilities.role) or "unknown"
        probe_connection = c_text(self.capabilities.connection_state) or "unknown"
        try:
            config = self.backend.read_status(self.device.mac)
        except (NativeError, ValueError):
            lines = ["CURRENT VALUES: UNKNOWN", "Read-back failed; stale values are not shown.", ""]
            lines.extend(self._target_lines())
            lines.extend([
                "Role: unknown", "Connection: unknown",
                f"Available: {capability_text(self.capabilities)}",
                f"Snapshot: {self.snapshot_state}",
            ])
            self.status_values = lines
            self._publish_status(note)
            return
        lines = [
            f"SSID: {c_text(config.ssid) or '<empty>'}",
            f"Channels (MHz): {format_channels(config_channels(config)) or 'unknown'}",
            f"Bandwidth: {config.bandwidth_mhz} MHz",
            f"TX power: {tx_power_text(config)}",
            f"Security: {c_text(config.encryption) or 'unknown'}",
            "",
        ]
        lines.extend(self._target_lines())
        lines.extend([
            f"Role: {c_text(config.role) or probe_role}",
            f"Connection: {c_text(config.connection_state) or probe_connection}",
            f"Available: {capability_text(self.capabilities)}",
            f"Snapshot: {self.snapshot_state}",
        ])
        self.status_values = lines
        self._publish_status(note)

    # -- menus and quitting -------------------------------------------------

    def _quit_confirmed(self) -> bool:
        if self.write_incomplete:
            return self.ui.confirm(
                "Quit utility",
                "The last write did not complete and the device may hold a partial "
                "configuration.\n\nQuit anyway?",
            )
        if self.session_wrote:
            return self.ui.confirm(
                "Quit utility",
                "Settings were written to a device during this session.\n\nQuit now?",
            )
        return True

    def _request_quit(self) -> bool:
        if self._quit_confirmed():
            self.quit_requested = True
            return True
        return False

    def _menu(self, title: str, items: Sequence[MenuItem], body: str = "",
              allow_cancel: bool = True, initial: int = 0) -> int:
        """ui.menu plus the quit guard; MENU_QUIT also sets quit_requested."""

        while True:
            choice = self.ui.menu(title, items, body, allow_cancel=allow_cancel, initial=initial)
            if choice != MENU_QUIT:
                return choice
            if self._request_quit():
                return MENU_QUIT

    def failure_dialog(
        self,
        message: str,
        *,
        restore_enabled: bool | None = None,
        retry_label: str = "Retry",
        rollback_notice: bool = True,
    ) -> int:
        enabled = self.snapshot is not None
        if restore_enabled is not None:
            enabled = restore_enabled
        body = message
        if rollback_notice:
            body += "\n\nNo automatic rollback was performed."
        choice = self._menu(
            "Operation did not complete",
            [MenuItem(retry_label), MenuItem("Ignore"), MenuItem("Restore snapshot", enabled)],
            body,
            allow_cancel=False,
        )
        if choice < 0:
            return FAILURE_IGNORE
        return choice

    # -- target selection ---------------------------------------------------

    def _forget_device(self) -> None:
        self.device = None
        self.capabilities = None
        self.snapshot = None
        self.snapshot_state = "none"
        self.manual_snapshot_checked = False

    def select_interface(self) -> InterfaceInfo | None:
        interfaces = self.backend.list_interfaces()
        if not interfaces:
            raise NativeError(STATUS_NOT_FOUND, "No eligible IPv4 broadcast interfaces were found.")
        if self.preselected_interface is not None:
            name = self.preselected_interface
            self.preselected_interface = None
            for item in interfaces:
                if item.name == name:
                    return item
            self.ui.message(
                "Interface not available",
                f"Interface {name} has no usable IPv4 broadcast address. Choose another.",
            )
        labels = [MenuItem(f"{item.name} — {item.address} → {item.broadcast}")
                  for item in interfaces]
        while True:
            choice = self._menu(
                "Select interface", labels,
                "Discovery is limited to the selected IPv4 broadcast domain.",
            )
            if choice >= 0:
                return interfaces[choice]
            if choice == MENU_QUIT:
                return None
            if self._request_quit():
                return None

    def select_device(self) -> tuple[int, DeviceInfo | None]:
        """Return (PICK_DONE, device), (MENU_BACK, None) or (MENU_QUIT, None)."""

        self.ui.progress("Scanning",
                         "Listening for TaiXin devices on the selected broadcast domain…")
        devices = self.backend.scan()
        if self.preselected_mac is not None:
            mac = self.preselected_mac
            self.preselected_mac = None
            for device in devices:
                if device.mac == mac:
                    return PICK_DONE, device
            self.ui.message(
                "Device not found",
                f"{':'.join(f'{byte:02x}' for byte in mac)} did not respond on "
                f"{self.interface.name if self.interface else 'this interface'}. Choose a device.",
            )
        labels = [MenuItem(f"{device.mac_text} — {device.response_address}")
                  for device in devices]
        choice = self._menu("Select exact MAC", labels,
                            "Select a device. Esc returns to interfaces.")
        if choice == MENU_QUIT:
            return MENU_QUIT, None
        if choice < 0:
            return MENU_BACK, None
        return PICK_DONE, devices[choice]

    def establish_target(self) -> int:
        while self.device is None:
            if self.interface is None:
                interface = self.select_interface()
                if interface is None:
                    return TARGET_QUIT
                self.backend.select_interface(interface)
                self.interface = interface
                self.refresh_status("Interface selected; awaiting target.")
            code, device = self.select_device()
            if code == MENU_QUIT:
                return TARGET_QUIT
            if device is None:
                self.interface = None
                self.refresh_status("Choose an IPv4 broadcast domain.")
                continue
            self.device = device
        self.refresh_status("Target selected; compatibility probe pending.")
        self.ui.progress("Compatibility probe",
                         f"Checking {self.device.mac_text} with read-only TaiXin queries…")
        self.capabilities = self.backend.probe(self.device.mac)
        self.ui.progress("Reading current setup",
                         f"Reading managed settings from {self.device.mac_text}…")
        self.refresh_status()
        return TARGET_READY

    # -- snapshots ------------------------------------------------------------

    def offer_snapshot(self) -> None:
        assert self.device is not None
        path = snapshot_path(self.data_root, self.device.mac)
        if path.exists():
            try:
                self.snapshot = load_snapshot(self.data_root, self.device.mac)
                self.snapshot_state = "loaded"
            except (StorageError, ValueError, UnicodeError) as error:
                self.snapshot_state = "unreadable"
                self.ui.message(
                    "Snapshot warning",
                    str(error) + "\nThe existing file will never be replaced or deleted; "
                    "restoration is disabled.",
                )
            self.refresh_status()
            return
        prompt = (
            "Do you want to create a configuration snapshot that will allow you to restore "
            f"the current configuration later?\n\nIt will be written to {path}."
        )
        if not self.ui.confirm("Immutable snapshot", prompt):
            return
        while True:
            config = None
            try:
                config = self.backend.read_config(self.device.mac)
                create_snapshot(self.data_root, config)
                self.snapshot = load_snapshot(self.data_root, self.device.mac)
                self.snapshot_state = "loaded"
                self.refresh_status()
                self.ui.message("Snapshot created",
                                f"Protected immutable snapshot created at {path}.")
                return
            except (NativeError, StorageError, ValueError, UnicodeError) as error:
                if self.failure_dialog(str(error), restore_enabled=False) == FAILURE_RETRY:
                    continue
                return
            finally:
                if config is not None:
                    config.psk = b""

    def restore_snapshot_workflow(self) -> None:
        assert self.device is not None
        if self.snapshot is None:
            return
        path = snapshot_path(self.data_root, self.device.mac)
        summary = (
            f"Snapshot: {path}\nTarget MAC: {self.device.mac_text}\n"
            + config_summary(self.snapshot)
            + "\n\nApply and verify every managed field?"
        )
        if not self.ui.confirm("Confirm snapshot restore", summary):
            return
        request = WriteRequest(WRITE_RESTORE, self.device.mac, config=self.snapshot)
        if self.run_action(request) == ACTION_VERIFIED:
            self.ui.success_message(
                "Restored",
                "configuration applied successfully\n\n"
                "Every managed snapshot field was reapplied and verified.",
            )

    # -- writes ---------------------------------------------------------------

    def run_action(self, request: WriteRequest) -> int:
        """Perform a write with retry; ACTION_VERIFIED only if the requested write was verified.

        A WRITE_SSID whose device PSK could not be read (nothing written) returns
        ACTION_PSK_UNREADABLE without a failure dialog so the caller can offer shared.psk."""

        current = request
        restoring_instead = False
        while True:
            self._publish_status("Operation in progress; values will refresh after completion.")
            self.ui.progress("Applying settings",
                             f"Writing to {mac_text(current.mac)} and verifying every field by "
                             "read-back…")
            try:
                perform_write(self.backend, current)
            except (NativeError, StorageError, ValueError) as error:
                if current.kind == WRITE_SSID and psk_snapshot_failed(error):
                    self._publish_status("SSID not changed; the device PSK could not be read.")
                    return ACTION_PSK_UNREADABLE
                partial = False
                if isinstance(error, NativeError) and error.result is not None:
                    partial = bool(error.result.applied_mask)
                self.write_incomplete = True
                self.last_write_partial = partial
                note = "Operation failed; current-state read-back was attempted."
                if partial:
                    note = "Partial update reported; current-state read-back was attempted."
                self.refresh_status(note)
                choice = self.failure_dialog(str(error))
                if choice == FAILURE_RETRY:
                    continue
                if choice == FAILURE_RESTORE and self.snapshot is not None:
                    current = WriteRequest(WRITE_RESTORE, request.mac, config=self.snapshot)
                    restoring_instead = True
                    continue
                return ACTION_ABANDONED
            self.session_wrote = True
            self.write_incomplete = False
            self.last_write_partial = False
            if restoring_instead:
                self.refresh_status("Snapshot restoration verified.")
                self.ui.success_message(
                    "Restored",
                    "configuration applied successfully\n\n"
                    "The requested change was abandoned; every managed snapshot field was "
                    "reapplied and verified instead.",
                )
                return ACTION_ABANDONED
            self.refresh_status("Last operation completed and verified.")
            return ACTION_VERIFIED

    # -- credentials ----------------------------------------------------------

    def _copy_device_psk(self, existing: bool, existing_psk: str | None) -> None:
        assert self.device is not None
        old_preview = "none"
        if existing_psk is not None:
            old_preview = psk_preview(existing_psk)
        elif existing:
            old_preview = "unavailable or malformed"
        psk_file = shared_psk_path(self.data_root)
        if not self.ui.confirm(
            "Copy device PSK",
            f"Selected MAC: {self.device.mac_text}\nExisting shared.psk: {old_preview}\n\n"
            f"Read the protected PSK from this device and atomically write it to {psk_file}?",
        ):
            return
        while True:
            copied_psk = ""
            try:
                copied_psk = self.backend.read_psk(self.device.mac)
                write_shared_psk(self.data_root, copied_psk)
                self._publish_status("PSK copied to shared.psk; device settings were not changed.")
                self.ui.message(
                    "PSK copied",
                    f"The selected device PSK ({psk_preview(copied_psk)}) was written to "
                    f"{psk_file}.\n\n" + ANOTHER_DEVICE_HINT,
                )
                return
            except (NativeError, StorageError, ValueError) as error:
                if self.failure_dialog(str(error), restore_enabled=False) != FAILURE_RETRY:
                    return
            finally:
                copied_psk = ""

    def _save_generated_psk(self, psk: str) -> str:
        """Write a verified generated key to shared.psk; return a sentence for the user."""

        psk_file = shared_psk_path(self.data_root)
        while True:
            try:
                write_shared_psk(self.data_root, psk)
                return f"shared.psk was updated with the new key: {psk_file}"
            except (StorageError, ValueError) as error:
                if self.failure_dialog(str(error), restore_enabled=False) != FAILURE_RETRY:
                    return (
                        f"shared.psk could NOT be updated ({psk_file}). The device uses the new "
                        "key; use 'Copy device PSK to shared.psk' to save it."
                    )

    def _ssid_only_workflow(self, mac: bytes, ssid: str, existing_psk: str | None) -> None:
        """Change only the SSID; the native transaction reads and reapplies the device PSK."""

        summary = (
            f"MAC: {mac.hex(':')}\nSSID: {ssid}\n"
            "PSK: unchanged (the device's current key is reapplied)\nSecurity: unchanged"
        )
        if not self.ui.confirm("Confirm credential update", summary + "\n\nApply these settings?"):
            return
        outcome = self.run_action(WriteRequest(WRITE_SSID, mac, ssid=ssid))
        detail = (
            "The SSID matched read-back. The device's protected PSK and WPA-PSK key management "
            "were preserved and verified."
        )
        if outcome == ACTION_PSK_UNREADABLE:
            outcome = self._ssid_with_psk_file(mac, ssid, existing_psk)
            if existing_psk is not None:
                detail = (
                    f"The SSID matched read-back. The PSK from shared.psk "
                    f"({psk_preview(existing_psk)}) and WPA-PSK key management were reapplied "
                    "and verified."
                )
        if outcome != ACTION_VERIFIED:
            return
        self.ui.success_message(
            "Credentials verified",
            "configuration applied successfully\n\n" + detail + "\n\nshared.psk was not changed."
            "\n\n" + PEER_PAIRING_HINT + "\n\n" + ANOTHER_DEVICE_HINT,
        )

    def _ssid_with_psk_file(self, mac: bytes, ssid: str, existing_psk: str | None) -> int:
        """Fallback when the device PSK is unreadable: reapply shared.psk after confirmation."""

        if existing_psk is None:
            self.ui.message(
                "SSID not changed",
                "The device did not return its current protected PSK, so the utility cannot "
                "safely use the firmware's reliable full credential transaction.\n\nCreate or "
                "repair shared.psk with the device's current key, or use 'Change SSID and PSK'. "
                "No settings were written.",
            )
            return ACTION_ABANDONED
        if not self.ui.confirm(
            "Use shared.psk to preserve PSK",
            "The device did not return its current protected PSK. No settings were written.\n\n"
            f"shared.psk: {psk_preview(existing_psk)}\n\n"
            "Use this as the existing key and reapply it while changing only the SSID?",
        ):
            return ACTION_ABANDONED
        request = WriteRequest(WRITE_CREDENTIALS, mac, ssid=ssid, psk=existing_psk)
        outcome = self.run_action(request)
        request.psk = ""
        return outcome

    def credentials_workflow(self) -> None:
        assert self.device is not None
        mac = self.device.mac
        psk_file = shared_psk_path(self.data_root)
        existing = shared_psk_exists(self.data_root)
        existing_psk: str | None = None
        existing_error = ""
        if existing:
            try:
                existing_psk = load_shared_psk(self.data_root)
            except StorageError as error:
                existing_error = str(error)
        body = f"The shared key file is {psk_file} and can be edited manually."
        if existing_psk is not None:
            body += f"\nExisting shared.psk: {psk_preview(existing_psk)}"
        elif existing_error:
            body += f"\nExisting shared.psk is unavailable: {existing_error}"
        action = self._menu(
            "SSID/PSK setup",
            [
                MenuItem("Change SSID and PSK"),
                MenuItem("Change SSID only"),
                MenuItem("Change PSK only"),
                MenuItem("Copy device PSK to shared.psk"),
            ],
            body,
        )
        if action < 0:
            return
        if action == CRED_COPY_DEVICE_PSK:
            self._copy_device_psk(existing, existing_psk)
            return

        ssid = ""
        if action == CRED_SSID_AND_PSK or action == CRED_SSID_ONLY:
            text = self.ui.input("SSID setup", "SSID (1–32 UTF-8 bytes):", maximum=SSID_MAX_BYTES)
            if text is None:
                return
            try:
                ssid = parse_ssid(text)
            except ValueError as error:
                self.ui.message("Invalid input", str(error))
                return
        if action == CRED_SSID_ONLY:
            self._ssid_only_workflow(mac, ssid, existing_psk)
            return

        psk_body = (
            body + "\nGenerated with Python’s secrets.token_bytes(32).hex(): "
            "32 random bytes encoded as 64 lowercase hexadecimal characters."
        )
        method = self._menu(
            "Select PSK",
            [
                MenuItem("Generate a new PSK with Python secrets"),
                MenuItem("Use existing shared.psk", existing_psk is not None),
            ],
            psk_body,
        )
        if method < 0:
            return
        psk = ""
        generated = False
        if method == PSK_GENERATE:
            if existing:
                old_preview = "unavailable or malformed"
                if existing_psk is not None:
                    old_preview = psk_preview(existing_psk)
                if not self.ui.confirm(
                    "Replace shared.psk",
                    f"Existing shared.psk: {old_preview}\n\nGenerate a new key? shared.psk will be "
                    "replaced only after the device has accepted and verified it. This "
                    "cannot be undone by the utility.",
                ):
                    return
            psk = generate_psk()
            generated = True
        else:
            if existing_psk is None:
                return
            psk = existing_psk

        summary = f"MAC: {mac.hex(':')}\n"
        if action == CRED_SSID_AND_PSK:
            summary += (
                f"SSID: {ssid}\nPSK: {psk_preview(psk)}\n"
                "Security: WPA-PSK (AES-CCMP support verified)"
            )
        else:
            summary += f"SSID: unchanged\nPSK: {psk_preview(psk)}\nSecurity: unchanged"
        if generated:
            summary += f"\n\n{psk_file} will be replaced with the new key after verification."
        if not self.ui.confirm("Confirm credential update", summary + "\n\nApply these settings?"):
            return

        if action == CRED_SSID_AND_PSK:
            request = WriteRequest(WRITE_CREDENTIALS, mac, ssid=ssid, psk=psk)
            detail = (
                f"The SSID and protected PSK ({psk_preview(psk)}) matched read-back; WPA-PSK key "
                "management and AES-CCMP support were verified."
            )
        else:
            request = WriteRequest(WRITE_PSK, mac, psk=psk)
            detail = (
                f"The protected PSK ({psk_preview(psk)}) matched read-back. The SSID and WPA-PSK "
                "key management remained unchanged."
            )
        outcome = self.run_action(request)
        request.psk = ""
        if outcome != ACTION_VERIFIED:
            # A partial write may have left the generated key on the device: offer to keep it
            # even when the user is quitting.
            if generated and (self.last_write_partial or not self.quit_requested):
                self._after_failed_generated_write(psk)
            return
        file_note = "shared.psk was not changed."
        if generated:
            file_note = self._save_generated_psk(psk)
        self.ui.success_message(
            "Credentials verified",
            "configuration applied successfully\n\n" + detail + "\n\n" + file_note + "\n\n"
            + PEER_PAIRING_HINT + "\n\n" + ANOTHER_DEVICE_HINT,
        )

    def _after_failed_generated_write(self, psk: str) -> None:
        psk_file = shared_psk_path(self.data_root)
        if not self.last_write_partial:
            self.ui.message(
                "shared.psk unchanged",
                f"The device did not verify the new key, so {psk_file} was not changed and the "
                "generated key was discarded.",
            )
            return
        if self.ui.confirm(
            "Partial update",
            "The device reported a partial update and may already use the generated key "
            f"({psk_preview(psk)}).\n\nWrite the generated key to {psk_file} anyway?",
        ):
            message = self._save_generated_psk(psk)
            self.ui.message("shared.psk", message)
            return
        self.ui.message(
            "shared.psk unchanged",
            f"{psk_file} was not changed. Use 'Copy device PSK to shared.psk' to save whatever "
            "key the device holds.",
        )

    # -- radio ------------------------------------------------------------------

    def _select_manual_channels(self, initial: tuple[int, ...]) -> tuple[int, tuple[int, ...]]:
        """Return (PICK_DONE, channels), (MENU_BACK, ()) or (MENU_QUIT, ())."""

        selected: list[int] = []
        for channel in initial:
            if channel not in selected:
                selected.append(channel)
        option_set = set(MANUAL_CHANNEL_OPTIONS_KHZ)
        for _tag, channels, _bandwidth in STANDARD_CHANNEL_SETS:
            option_set.update(channels)
        option_set.update(selected)
        options = sorted(option_set)
        cursor = TOGGLE_DONE
        while True:
            labels = [MenuItem(f"Done — use {len(selected)} selected channel(s)", bool(selected))]
            selection_full = len(selected) >= MAX_CHANNELS
            for channel in options:
                mark = " "
                if channel in selected:
                    mark = "x"
                enabled = channel in selected or not selection_full
                labels.append(MenuItem(f"[{mark}] {channel / 1000:.1f} MHz", enabled))
            choice = self._menu(
                "Select channel centres",
                labels,
                "Toggle 1–16 exact centres; disjoint lists are fine.",
                initial=cursor,
            )
            if choice == MENU_QUIT:
                return MENU_QUIT, ()
            if choice < 0:
                return MENU_BACK, ()
            if choice == TOGGLE_DONE:
                return PICK_DONE, tuple(sorted(selected))
            channel = options[choice - 1]
            if channel in selected:
                selected.remove(channel)
            else:
                selected.append(channel)
            # Keep the cursor on the toggled row so neighbouring centres are one key away.
            cursor = choice

    def _select_channel_configuration(
        self, initial: tuple[int, ...], bandwidth: int,
    ) -> tuple[int, tuple[int, ...], int]:
        """Return (PICK_DONE, channels, bandwidth), or (MENU_BACK|MENU_QUIT, (), 0)."""

        while True:
            mode = self._menu(
                "Channel selection",
                [
                    MenuItem("Standard ranges"),
                    MenuItem("Individual channel centres (advanced)"),
                ],
                "Standard ranges use TaiXin’s published CE/FCC/MIC centre sets. They do not by "
                "themselves establish legal operation.",
            )
            if mode == MENU_QUIT:
                return MENU_QUIT, (), 0
            if mode < 0:
                return MENU_BACK, (), 0
            if mode == CHANNEL_MODE_STANDARD:
                labels = []
                for tag, channels, set_bandwidth in STANDARD_CHANNEL_SETS:
                    labels.append(MenuItem(standard_set_label(tag, channels, set_bandwidth)))
                choice = self._menu(
                    "Standard channel ranges",
                    labels,
                    "Choosing a range also selects its required channel bandwidth. TX power "
                    "remains unchanged.\n" + STANDARD_SETS_HELP,
                )
                if choice == MENU_QUIT:
                    return MENU_QUIT, (), 0
                if choice == MENU_BACK:
                    continue
                _tag, channels, selected_bandwidth = STANDARD_CHANNEL_SETS[choice]
                return PICK_DONE, channels, selected_bandwidth
            code, selected = self._select_manual_channels(initial)
            if code == MENU_QUIT:
                return MENU_QUIT, (), 0
            if code == PICK_DONE:
                return PICK_DONE, selected, bandwidth

    def _manual_radio(self) -> tuple[int, tuple[int, ...], int, int]:
        """Return (PICK_DONE, channels, bandwidth, power), or (MENU_BACK|MENU_QUIT, (), 0, 0)."""

        assert self.device is not None
        self.ui.progress("Manual radio setup", "Reading the current radio values before editing…")
        try:
            current = self.backend.read_status(self.device.mac)
        except (NativeError, ValueError) as error:
            self.ui.message("Radio values unavailable", str(error))
            return MENU_BACK, (), 0, 0
        channels = config_channels(current)
        bandwidth = DEFAULT_BANDWIDTH_MHZ
        if current.bandwidth_mhz in BANDWIDTHS_MHZ:
            bandwidth = current.bandwidth_mhz
        power = DEFAULT_TX_POWER_DBM
        # Start from the saved setting: the live value can sit above it (PA control),
        # and applying it unchanged would raise the setting.
        if current.stored_tx_power_dbm in TX_POWER_OPTIONS_DBM:
            power = current.stored_tx_power_dbm
        while True:
            centres = format_channels(channels) or "none"
            choice = self._menu(
                "Manual radio setup",
                [
                    MenuItem(f"Channel centres — {centres} MHz"),
                    MenuItem(f"Bandwidth — {bandwidth} MHz"),
                    MenuItem(f"TX power — {power} dBm"),
                    MenuItem("Review these settings"),
                ],
                "Select each field from its predefined options. No setting is written until the "
                "final regulatory confirmation.",
            )
            if choice == MENU_QUIT:
                return MENU_QUIT, (), 0, 0
            if choice < 0:
                return MENU_BACK, (), 0, 0
            if choice == MANUAL_CHANNELS:
                code, updated, updated_bandwidth = self._select_channel_configuration(
                    channels, bandwidth
                )
                if code == MENU_QUIT:
                    return MENU_QUIT, (), 0, 0
                if code == PICK_DONE:
                    channels = updated
                    bandwidth = updated_bandwidth
            elif choice == MANUAL_BANDWIDTH:
                labels = []
                for value in BANDWIDTHS_MHZ:
                    suffix = ""
                    if value == bandwidth:
                        suffix = " — current"
                    labels.append(MenuItem(f"{value} MHz{suffix}"))
                picked = self._menu("Select bandwidth", labels,
                                    initial=index_of(BANDWIDTHS_MHZ, bandwidth))
                if picked == MENU_QUIT:
                    return MENU_QUIT, (), 0, 0
                if picked >= 0:
                    bandwidth = BANDWIDTHS_MHZ[picked]
            elif choice == MANUAL_TX_POWER:
                labels = []
                for value in TX_POWER_OPTIONS_DBM:
                    suffix = ""
                    if value == power:
                        suffix = " — current"
                    labels.append(MenuItem(f"{value} dBm{suffix}"))
                picked = self._menu("Select TX power", labels,
                                    initial=index_of(TX_POWER_OPTIONS_DBM, power))
                if picked == MENU_QUIT:
                    return MENU_QUIT, (), 0, 0
                if picked >= 0:
                    power = TX_POWER_OPTIONS_DBM[picked]
            else:
                if not channels:
                    self.ui.message("No channels", "Select at least one channel centre first.")
                    continue
                return PICK_DONE, channels, bandwidth, power

    def _preset_radio(self) -> tuple[int, RadioPreset | None]:
        """Return (PICK_DONE, preset), or (MENU_BACK|MENU_QUIT, None)."""

        try:
            presets = load_presets(self.preset_directory)
        except PresetError as error:
            self.ui.message("Preset rejected", str(error))
            return MENU_BACK, None
        if not presets:
            self.ui.message(
                "No presets found",
                f"No radio presets were found in {self.preset_directory}. Add schema-version-1 "
                "TOML files only after validating the applicable rules.",
            )
            return MENU_BACK, None
        labels = []
        for item in presets:
            labels.append(MenuItem(item.name))
        choice = self._menu(
            "Radio preset", labels,
            "The jurisdiction, source and warning are shown for review before anything is written.",
        )
        if choice == MENU_QUIT:
            return MENU_QUIT, None
        if choice < 0:
            return MENU_BACK, None
        return PICK_DONE, presets[choice]

    def radio_workflow(self) -> None:
        assert self.device is not None
        mode = self._menu("Radio setup", [MenuItem("Manual"), MenuItem("Preset")])
        if mode < 0:
            return
        preset: RadioPreset | None = None
        if mode == RADIO_MANUAL:
            code, channels, bandwidth, power = self._manual_radio()
            if code != PICK_DONE:
                return
        else:
            code, preset = self._preset_radio()
            if code != PICK_DONE or preset is None:
                return
            channels = preset.channels_khz
            bandwidth = preset.bandwidth_mhz
            power = preset.tx_power_dbm
        body = radio_confirm_body(self.device.mac_text, channels, bandwidth, power, preset)
        if not self.ui.confirm("Regulatory warning", body):
            return
        request = WriteRequest(WRITE_RADIO, self.device.mac, channels_khz=tuple(channels),
                               bandwidth_mhz=bandwidth, tx_power_dbm=power)
        if self.run_action(request) == ACTION_VERIFIED:
            self.ui.success_message(
                "Radio verified",
                "configuration applied successfully\n\n"
                "Bandwidth, channel list and TX power setting all matched read-back.",
            )

    # -- full configurations ------------------------------------------------------

    def backup_full_configuration(self) -> None:
        assert self.device is not None
        name = self.ui.input(
            "Back up full configuration",
            "Name this configuration (letters, digits, spaces, '.', '_' or '-'): ",
            maximum=CONFIG_NAME_MAX,
        )
        if name is None:
            return
        self.ui.progress("Back up full configuration",
                         f"Reading every managed field from {self.device.mac_text}…")
        config = None
        try:
            config = self.backend.read_config(self.device.mac)
            path = create_saved_configuration(self.data_root, name, config)
        except (NativeError, StorageError, ValueError, UnicodeError) as error:
            self.ui.message("Backup not created", str(error))
            return
        finally:
            if config is not None:
                config.psk = b""
        self._publish_status(f"Full configuration backed up as {path.name}.")
        self.ui.message(
            "Configuration backed up",
            f"Saved every managed field to {path}.\n\n{path.name} has been successfully created.",
        )

    def apply_saved_configuration(self) -> None:
        assert self.device is not None
        directory = self.data_root / "configs"
        try:
            saved, errors = list_saved_configurations(self.data_root, self.device.mac)
        except (StorageError, ValueError) as error:
            self.ui.message("Saved configuration unavailable", str(error))
            return
        skipped = ""
        if errors:
            skipped = "\n\nIgnored invalid files:"
            # Each reason already names its file.
            for _filename, reason in errors:
                skipped += f"\n- {reason}"
        if not saved:
            self.ui.message(
                "No saved configurations",
                f"No valid mode-0600 INI configurations exist in {directory}." + skipped,
            )
            return
        labels = []
        for item in saved:
            labels.append(MenuItem(f"{item.name} — source {item.source_mac.hex(':')}"))
        selected = None
        try:
            choice = self._menu(
                "Apply saved configuration",
                labels,
                "Select a full configuration to apply to the currently selected device." + skipped,
            )
            if choice < 0:
                return
            selected = saved[choice]
            summary = (
                f"Saved configuration: {selected.name}\n"
                f"Source MAC: {selected.source_mac.hex(':')}\n"
                f"Target MAC: {self.device.mac_text}\n"
                + config_summary(selected.config)
                + "\n\nApply and verify every managed field?"
            )
            if not self.ui.confirm("Confirm full configuration", summary):
                return
            request = WriteRequest(WRITE_RESTORE, self.device.mac, config=selected.config)
            if self.run_action(request) == ACTION_VERIFIED:
                self.ui.success_message(
                    "Configuration applied",
                    "configuration applied successfully\n\n"
                    f"Saved configuration '{selected.name}' was applied and every managed field "
                    "matched read-back.",
                )
        finally:
            for item in saved:
                item.config.psk = b""

    # -- main loop ---------------------------------------------------------------

    # -- manual AT commands -----------------------------------------------------

    def _manual_catalog(self) -> list[CatalogEntry]:
        """The catalogue, loaded once; an unreadable one falls back to shape-only checks."""

        if self.catalog is not None:
            return self.catalog
        try:
            self.catalog = load_catalog()
        except CatalogError as error:
            self.catalog = []
            self.ui.message(
                "Catalogue unavailable",
                f"{error}\n\nYou can still type commands. They are classified by shape: "
                "AT+NAME? is a query, AT+NAME=... is a set, anything else is unknown.",
            )
        return self.catalog

    def manual_at_workflow(self) -> None:
        assert self.device is not None
        catalog = self._manual_catalog()
        ordered = catalog_in_name_order(catalog)
        items = [MenuItem("Type any command…  (:)")]
        names = [""]
        bodies = [FREE_ROW_BODY]
        for entry in ordered:
            items.append(MenuItem(catalog_row_label(entry)))
            names.append(entry.name)
            bodies.append(catalog_entry_body(entry))
        selected = CATALOG_FREE_ROW
        while not self.quit_requested:
            code, selected = self.ui.pick("Manual AT command dispatch", items, names, bodies, selected)
            if code == MENU_BACK:
                return
            draft = ""
            if selected != CATALOG_FREE_ROW and code != PICK_FREE:
                draft = initial_draft(ordered[selected - 1])
            if code == PICK_EDITOR:
                result, draft = self._edit_payload(catalog, draft)
                if result != PAYLOAD_LINE:
                    continue
            self._edit_and_send(catalog, draft)

    def _remember_command(self, command: str) -> None:
        if self.at_history and self.at_history[-1] == command:
            return
        self.at_history.append(command)
        if len(self.at_history) > AT_HISTORY_MAX:
            del self.at_history[0]

    def _edit_and_send(self, catalog: list[CatalogEntry], draft: str) -> None:
        assert self.device is not None
        prompt = (
            f"Device {self.device.mac_text}. Queries are sent at once; set commands ask "
            "Yes/No; action and unknown commands ask you to type their name. A snapshot is "
            "taken before the first write if none exists. Replies hide PSKs."
        )
        text = draft
        while not self.quit_requested:
            result, text = self.ui.edit_line("AT command", prompt, text, self.at_history)
            if result == LINE_CANCEL:
                return
            if result == LINE_EDITOR:
                edited, payload = self._edit_payload(catalog, text)
                if edited == PAYLOAD_BATCH:
                    return
                text = payload
                continue
            command = text.strip()
            if not command:
                continue
            self._remember_command(command)
            choice = self._send_manual(catalog, command)
            while choice == AT_REPLY_SEND_AGAIN:
                choice = self._send_manual(catalog, command)
            if choice == AT_REPLY_EDIT:
                text = command
                continue
            return

    def _confirm_manual(self, checked: CheckedCommand) -> bool:
        """Queries need nothing, sets a Yes/No, actions and unknown commands their typed name."""

        assert self.device is not None
        if checked.command_class == CLASS_QUERY:
            return True
        shown = redact_command(checked.text)
        about = entry_about(checked.entry)
        if checked.command_class == CLASS_SET:
            return self.ui.confirm(
                "Send set command",
                f"{shown}\n\nThis changes a device setting.\n{about}\n\n"
                f"Send it to {self.device.mac_text}?",
            )
        word = command_name(normalize_command(checked.text)) or SEND_ALL_WORD
        warning = UNKNOWN_COMMAND_WARNING
        if checked.command_class == CLASS_ACTION:
            warning = ACTION_COMMAND_WARNING
        typed = self.ui.input(
            f"Confirm {checked.command_class} command",
            f"{shown}\n\n{warning}\n{about}\n\nType {word} to send it to "
            f"{self.device.mac_text}, or press Esc to cancel.",
            maximum=AT_COMMAND_MAX,
        )
        if typed is None:
            return False
        if typed.strip().upper() != word.upper():
            self.ui.message("Not sent", "The typed text did not match; nothing was sent.")
            return False
        return True

    def _snapshot_before_manual_write(self) -> tuple[bool, str]:
        """Return (may write, note); creates the device snapshot once if none exists yet."""

        assert self.device is not None
        if self.manual_snapshot_checked:
            return True, ""
        outcome = snapshot_before_write(self.backend, self.data_root, self.device.mac)
        if outcome.result == SNAPSHOT_FAILED:
            self.ui.message(
                "Not sent",
                "A snapshot is taken before the first write, and it could not be created: "
                f"{outcome.message}\n\nNothing was written.",
            )
            return False, ""
        self.manual_snapshot_checked = True
        if outcome.result != SNAPSHOT_CREATED:
            return True, ""
        try:
            self.snapshot = load_snapshot(self.data_root, self.device.mac)
            self.snapshot_state = "loaded"
        except (StorageError, ValueError, UnicodeError):
            self.snapshot_state = "unreadable"
        return True, f"Snapshot created at {outcome.path} before this first write."

    def _send_manual(self, catalog: list[CatalogEntry], command: str) -> int:
        """Check, confirm, send one command and show its reply; return an AT_REPLY_* choice."""

        assert self.device is not None
        checked = check_command(command, catalog)
        if checked.result != CHECK_OK:
            self.ui.message("Not sent",
                            f"{redact_command(command)}\n\n{checked.problem}. Nothing was sent.")
            return AT_REPLY_EDIT
        if not self._confirm_manual(checked):
            return AT_REPLY_EDIT
        note = ""
        if checked.command_class != CLASS_QUERY:
            allowed, note = self._snapshot_before_manual_write()
            if not allowed:
                return AT_REPLY_EDIT
        self.ui.progress("Sending", f"{redact_command(command)} → {self.device.mac_text}")
        started = self.ui.clock()
        try:
            reply = self.backend.raw_query(self.device.mac, command,
                                           timeout_ms=DEFAULT_REPLY_TIMEOUT_MS,
                                           idle_ms=DEFAULT_REPLY_IDLE_MS)
        except NativeError as error:
            self.ui.message("Command failed", f"{redact_command(command)}\n\n{error}")
            return AT_REPLY_EDIT
        elapsed_ms = int((self.ui.clock() - started) * MILLISECONDS_PER_SECOND)
        if checked.command_class != CLASS_QUERY:
            self.session_wrote = True
            self.refresh_status("Manual command sent; values refreshed.")
        choice = self._menu(
            "AT reply",
            [MenuItem("Send again"), MenuItem("Edit command"), MenuItem("Back to catalogue")],
            reply_report(checked, reply.status, reply.text, elapsed_ms, note),
        )
        if choice == MENU_QUIT:
            return AT_REPLY_CATALOG
        if choice == MENU_BACK:
            return AT_REPLY_EDIT
        return choice

    def _run_editor(self, payload: str) -> tuple[int, str]:
        """Open just the payload in $EDITOR; return (exit code, edited text).

        The exit code is EDITOR_UNAVAILABLE when no editor could be started."""

        argv = editor_command()
        if not argv:
            self.ui.message("No editor", "Set $VISUAL or $EDITOR, or install vim. Nothing was sent.")
            return EDITOR_UNAVAILABLE, ""
        # mkstemp creates the file with mode 0600; it is removed as soon as it is read.
        descriptor, name = tempfile.mkstemp(prefix="ahnb-at-", suffix=".txt")
        path = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                if payload:
                    stream.write(payload + "\n")
            # A bare name keeps the temp directory off the editor's status line.
            code = self.ui.run_external(argv + [path.name], str(path.parent))
            if code == EDITOR_UNAVAILABLE:
                self.ui.message("No editor", f"Could not start {argv[0]}. Nothing was sent.")
                return code, ""
            if code != 0:
                self.ui.message("Editor aborted",
                                f"{argv[0]} exited with status {code}; nothing was sent.")
                return code, ""
            text = path.read_text(encoding="utf-8", errors="replace")
        finally:
            path.unlink(missing_ok=True)
        return 0, text

    def _edit_payload(self, catalog: list[CatalogEntry], payload: str) -> tuple[int, str]:
        """^G: edit the payload in $EDITOR.

        One line comes back to the command line (PAYLOAD_LINE, line); several lines are
        a batch, reviewed and sent here (PAYLOAD_BATCH); an aborted edit or an empty
        file leaves the command line as it was (PAYLOAD_UNCHANGED, payload)."""

        code, text = self._run_editor(payload)
        if code != 0:
            return PAYLOAD_UNCHANGED, payload
        lines = batch_lines(text)
        if not lines:
            return PAYLOAD_UNCHANGED, payload
        if len(lines) == 1:
            return PAYLOAD_LINE, lines[0]
        self._run_batch(catalog, lines)
        return PAYLOAD_BATCH, ""

    def _run_batch(self, catalog: list[CatalogEntry], lines: list[str]) -> None:
        """Review a multi-line payload, then send it in order; "edit again" reopens it."""

        while not self.quit_requested:
            checked_list: list[CheckedCommand] = []
            for line in lines:
                checked_list.append(check_command(line, catalog))
            choice = self._review_batch(checked_list)
            if choice == BATCH_SEND:
                choice = self._send_batch(checked_list)
            if choice != BATCH_EDIT:
                return
            code, text = self._run_editor("\n".join(lines))
            if code != 0:
                return
            edited = batch_lines(text)
            if not edited:
                self.ui.message("Nothing sent", "The edited batch held no commands.")
                return
            lines = edited

    def _review_batch(self, checked_list: list[CheckedCommand]) -> int:
        lines: list[str] = []
        blocked = 0
        writes = 0
        for index in range(len(checked_list)):
            checked = checked_list[index]
            line = f"{index + 1}. {redact_command(checked.text)}  [{checked.command_class}]"
            if checked.result != CHECK_OK:
                line += f" — {checked.problem}"
                blocked += 1
            elif checked.command_class != CLASS_QUERY:
                writes += 1
            lines.append(line)
        lines.append("")
        if blocked:
            lines.append(f"{blocked} command(s) cannot be sent. Edit the batch to fix them.")
        elif writes:
            lines.append(f"{writes} command(s) change the device; you will confirm before "
                         "sending. Sending stops at the first failure.")
        else:
            lines.append("Queries only. Sending stops at the first failure.")
        choice = self._menu(
            "Review AT batch",
            [
                MenuItem(f"Send {len(checked_list)} command(s)", blocked == 0),
                MenuItem("Edit again in the editor"),
                MenuItem("Back to catalogue"),
            ],
            "\n".join(lines),
        )
        if choice < 0:
            return BATCH_CATALOG
        return choice

    def _confirm_batch(self, checked_list: list[CheckedCommand]) -> bool:
        assert self.device is not None
        dangerous = 0
        writes = 0
        for checked in checked_list:
            if checked.command_class == CLASS_SET:
                writes += 1
            elif checked.command_class != CLASS_QUERY:
                dangerous += 1
        if dangerous:
            typed = self.ui.input(
                "Confirm AT batch",
                f"The batch holds {dangerous} action or unknown command(s).\n\n"
                f"{ACTION_COMMAND_WARNING}\n\nType {SEND_ALL_WORD} to send the batch to "
                f"{self.device.mac_text}, or press Esc to cancel.",
                maximum=AT_COMMAND_MAX,
            )
            if typed is None:
                return False
            if typed.strip().upper() != SEND_ALL_WORD:
                self.ui.message("Not sent", "The typed text did not match; nothing was sent.")
                return False
            return True
        if writes:
            return self.ui.confirm(
                "Confirm AT batch",
                f"The batch holds {writes} set command(s) that change device settings.\n\n"
                f"Send it to {self.device.mac_text}?",
            )
        return True

    def _send_batch(self, checked_list: list[CheckedCommand]) -> int:
        """Send in order, stopping at the first failure; return BATCH_EDIT or BATCH_CATALOG."""

        assert self.device is not None
        if not self._confirm_batch(checked_list):
            return BATCH_CATALOG
        has_write = False
        for checked in checked_list:
            if checked.command_class != CLASS_QUERY:
                has_write = True
        note = ""
        if has_write:
            allowed, note = self._snapshot_before_manual_write()
            if not allowed:
                return BATCH_CATALOG
        reports: list[str] = []
        if note:
            reports.append(note)
        sent = 0
        wrote = False
        for checked in checked_list:
            self.ui.progress(
                "Sending AT batch",
                f"{sent + 1}/{len(checked_list)}: {redact_command(checked.text)}",
            )
            started = self.ui.clock()
            try:
                reply = self.backend.raw_query(self.device.mac, checked.text,
                                               timeout_ms=DEFAULT_REPLY_TIMEOUT_MS,
                                               idle_ms=DEFAULT_REPLY_IDLE_MS)
            except NativeError as error:
                reports.append(f"{redact_command(checked.text)}\nFailed: {error}")
                break
            sent += 1
            if checked.command_class != CLASS_QUERY:
                wrote = True
            elapsed_ms = int((self.ui.clock() - started) * MILLISECONDS_PER_SECOND)
            reports.append(reply_report(checked, reply.status, reply.text, elapsed_ms, ""))
            if reply.status == STATUS_TIMEOUT or reply_is_device_error(reply.text):
                break
        if sent < len(checked_list):
            reports.append(f"Stopped at the first failure; {len(checked_list) - sent} "
                           "command(s) were not sent.")
        if wrote:
            self.session_wrote = True
            self.refresh_status("Manual batch sent; values refreshed.")
        choice = self._menu(
            "AT batch result",
            [MenuItem("Back to catalogue"), MenuItem("Edit again in the editor")],
            "\n\n".join(reports),
        )
        if choice == RESULT_EDIT:
            return BATCH_EDIT
        return BATCH_CATALOG

    def main_menu(self) -> None:
        assert self.device is not None and self.capabilities is not None
        flags = self.capabilities.flags
        credentials = bool(flags & CAP_CREDENTIALS)
        radio = bool(flags & CAP_RADIO)
        full_configuration = credentials and radio
        while not self.quit_requested:
            choice = self._menu(
                "Main menu",
                [
                    MenuItem("SSID/PSK setup", credentials),
                    MenuItem("Radio setup", radio),
                    MenuItem("Back up full configuration", full_configuration),
                    MenuItem("Apply saved configuration", full_configuration),
                    MenuItem("Restore snapshot", full_configuration and self.snapshot is not None),
                    MenuItem("Manual AT command dispatch"),
                ],
                f"Device {self.device.mac_text}. Esc returns to device selection.",
            )
            if choice < 0:
                return
            if choice == MAIN_CREDENTIALS:
                self.credentials_workflow()
            elif choice == MAIN_RADIO:
                self.radio_workflow()
            elif choice == MAIN_BACKUP:
                self.backup_full_configuration()
            elif choice == MAIN_APPLY_SAVED:
                self.apply_saved_configuration()
            elif choice == MAIN_RESTORE_SNAPSHOT:
                self.restore_snapshot_workflow()
            elif choice == MAIN_MANUAL_AT:
                self.manual_at_workflow()

    def run(self) -> None:
        try:
            while not self.quit_requested:
                try:
                    status = self.establish_target()
                except NativeError as error:
                    self.interface = None
                    self._forget_device()
                    self.refresh_status("Choose an IPv4 broadcast domain.")
                    # Retry and Ignore both return to interface selection; only Quit exits.
                    self.failure_dialog(
                        str(error),
                        restore_enabled=False,
                        retry_label="Back to broadcast domain selection",
                        rollback_notice=False,
                    )
                    if self.quit_requested:
                        return
                    continue
                if status == TARGET_QUIT:
                    return
                self.offer_snapshot()
                if self.quit_requested:
                    return
                self.main_menu()
                self._forget_device()
                self.refresh_status("Select a device.")
        finally:
            self.backend.close()
