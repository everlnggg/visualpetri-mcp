from __future__ import annotations

import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any

from .core import PetriError
from .render import calculate_layout


def find_visualpetri(explicit_path: str | None = None) -> Path:
    candidates = [
        explicit_path,
        os.environ.get("VISUALPETRI_EXE"),
        str(Path.cwd() / "5_Сети Петри" / "Программа Сети Петри" / "VisualPetri.exe"),
        str(Path(__file__).resolve().parents[2] / "5_Сети Петри" / "Программа Сети Петри" / "VisualPetri.exe"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise PetriError(
        "VisualPetri.exe was not found. Set VISUALPETRI_EXE or pass executable_path."
    )


def launch_visualpetri(executable_path: str | None = None) -> dict[str, Any]:
    executable = find_visualpetri(executable_path)
    system = platform.system()
    if system == "Windows":
        process = subprocess.Popen([str(executable)], cwd=str(executable.parent))
    else:
        wine = next(
            (path for path in ("wine", "wine64") if _which(path)),
            None,
        )
        if not wine:
            raise PetriError(
                "VisualPetri is a 32-bit Windows application. Direct launch needs Windows "
                "or Wine. The MCP renderer remains fully available on this platform."
            )
        process = subprocess.Popen([wine, str(executable)], cwd=str(executable.parent))
    return {"pid": process.pid, "executable": str(executable), "platform": system}


def _which(name: str) -> str | None:
    from shutil import which

    return which(name)


def _windows_api():
    if platform.system() != "Windows":
        raise PetriError("VisualPetri desktop automation is supported only on Windows")
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    return ctypes, wintypes, user32


def _find_window(timeout: float = 12.0):
    ctypes, wintypes, user32 = _windows_api()
    matches: list[int] = []
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def callback(hwnd, _lparam):
        length = user32.GetWindowTextLengthW(hwnd)
        if length:
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            if "VisualPetri" in buffer.value and user32.IsWindowVisible(hwnd):
                matches.append(hwnd)
        return True

    callback_ref = callback_type(callback)
    deadline = time.time() + timeout
    while time.time() < deadline:
        matches.clear()
        user32.EnumWindows(callback_ref, 0)
        if matches:
            return matches[0]
        time.sleep(0.25)
    raise PetriError("VisualPetri window was not found")


def _click(hwnd, x: int, y: int, *, double: bool = False) -> None:
    ctypes, wintypes, user32 = _windows_api()
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    screen_x, screen_y = rect.left + x, rect.top + y
    user32.SetCursorPos(screen_x, screen_y)
    down, up = 0x0002, 0x0004
    user32.mouse_event(down, 0, 0, 0, 0)
    user32.mouse_event(up, 0, 0, 0, 0)
    if double:
        time.sleep(0.06)
        user32.mouse_event(down, 0, 0, 0, 0)
        user32.mouse_event(up, 0, 0, 0, 0)
    time.sleep(0.06)


def _hotkey(*keys: int) -> None:
    _ctypes, _wintypes, user32 = _windows_api()
    keyup = 0x0002
    for key in keys:
        user32.keybd_event(key, 0, 0, 0)
    for key in reversed(keys):
        user32.keybd_event(key, 0, keyup, 0)
    time.sleep(0.2)


def _paste_text(value: str) -> None:
    ctypes, _wintypes, user32 = _windows_api()
    kernel32 = ctypes.windll.kernel32
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.restype = ctypes.c_void_p
    encoded = (value + "\0").encode("utf-16-le")
    handle = kernel32.GlobalAlloc(0x0042, len(encoded))  # GMEM_MOVEABLE | GMEM_ZEROINIT
    if not handle:
        raise PetriError("Could not allocate Windows clipboard memory")
    pointer = kernel32.GlobalLock(handle)
    ctypes.memmove(pointer, encoded, len(encoded))
    kernel32.GlobalUnlock(handle)
    if not user32.OpenClipboard(None):
        kernel32.GlobalFree(handle)
        raise PetriError("Could not open Windows clipboard")
    try:
        user32.EmptyClipboard()
        user32.SetClipboardData(13, handle)  # CF_UNICODETEXT; clipboard owns handle
    finally:
        user32.CloseClipboard()
    _hotkey(0x11, 0x56)  # Ctrl+V


def draw_project_in_visualpetri(
    project: dict[str, Any],
    *,
    executable_path: str | None = None,
    save_as: str | None = None,
    clear_existing: bool = True,
) -> dict[str, Any]:
    """Best-effort automation of the original v1.0 UI on a visible Windows desktop.

    The method intentionally uses only Win32 APIs, so Codex and Claude Code do not
    need pywinauto. VisualPetri must use its default toolbar arrangement and 100% DPI.
    """
    if platform.system() != "Windows":
        raise PetriError(
            "The original VisualPetri UI can only be driven on Windows. Use petri_render "
            "and petri_export_report_bundle on macOS/Linux."
        )
    try:
        hwnd = _find_window(timeout=1.0)
    except PetriError:
        launch_visualpetri(executable_path)
        hwnd = _find_window()
    ctypes, _wintypes, user32 = _windows_api()
    user32.ShowWindow(hwnd, 3)  # SW_MAXIMIZE
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.5)
    if clear_existing:
        _hotkey(0x11, 0x4E)  # Ctrl+N
        time.sleep(0.3)

    # Coordinates for the default VisualPetri v1.0 MDI layout at 100% Windows scale.
    # The drawing canvas is normalized independently from the report renderer.
    toolbar = {
        "select": (18, 126),
        "place": (18, 154),
        "transition": (18, 182),
        "arc": (18, 210),
    }
    canvas_left, canvas_top, canvas_right, canvas_bottom = 55, 135, 1180, 760
    layout, _, _ = calculate_layout(project, width=1800, height=1000)
    node_positions: dict[str, tuple[int, int]] = {}
    for node_id, (x, y) in layout.items():
        px = int(canvas_left + (canvas_right - canvas_left) * max(0, min(1, (x - 120) / 1560)))
        py = int(canvas_top + (canvas_bottom - canvas_top) * max(0, min(1, (y - 150) / 720)))
        node_positions[node_id] = (px, py)

    _click(hwnd, *toolbar["place"])
    for place in project.get("places", []):
        _click(hwnd, *node_positions[place["id"]])
    _click(hwnd, *toolbar["transition"])
    for transition in project.get("transitions", []):
        _click(hwnd, *node_positions[transition["id"]])
    _click(hwnd, *toolbar["arc"])
    for arc in project.get("arcs", []):
        _click(hwnd, *node_positions[arc["source"]])
        _click(hwnd, *node_positions[arc["target"]])

    # The original program adds a token by clicking an existing place while the
    # place tool is active (the behavior documented on methodical guide page 82).
    _click(hwnd, *toolbar["place"])
    for place_id, count in project.get("initial_marking", {}).items():
        for _ in range(count):
            _click(hwnd, *node_positions[place_id])
    _click(hwnd, *toolbar["select"])

    saved = None
    if save_as:
        target = Path(save_as).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        _hotkey(0x12, 0x46)  # Alt+F
        _hotkey(0x41)  # A: Save As in the English VisualPetri menu
        time.sleep(0.5)
        _paste_text(str(target))
        _hotkey(0x0D)
        saved = str(target)
        time.sleep(0.8)
    return {
        "drawn": True,
        "window_handle": int(hwnd),
        "places": len(project.get("places", [])),
        "transitions": len(project.get("transitions", [])),
        "arcs": len(project.get("arcs", [])),
        "saved_as": saved,
        "note": "Labels are exported by the MCP renderer; VisualPetri v1.0 itself stores only graphical elements.",
    }


def capture_visualpetri(output_path: str) -> dict[str, Any]:
    if platform.system() != "Windows":
        raise PetriError("VisualPetri window capture is supported only on Windows")
    try:
        from PIL import ImageGrab
    except ImportError as exc:
        raise PetriError("Window capture requires Pillow") from exc
    ctypes, wintypes, user32 = _windows_api()
    hwnd = _find_window()
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    image = ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom), all_screens=True)
    image.save(path, format="PNG")
    return {"captured": True, "path": str(path), "size": list(image.size)}
