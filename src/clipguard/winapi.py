"""Thin ctypes wrappers around the Win32 APIs ClipGuard needs.

Only importable on Windows. Nothing here reads clipboard *content*; that
stays in pyperclip. These helpers deal with keyboard hooks, focus and input.
"""

from __future__ import annotations

import ctypes
import logging
import os
import threading
from ctypes import wintypes
from typing import Callable

log = logging.getLogger("clipguard")

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

ULONG_PTR = ctypes.c_size_t
LRESULT = ctypes.c_ssize_t

WH_KEYBOARD_LL = 13
HC_ACTION = 0
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x100, 0x101, 0x104, 0x105
WM_QUIT = 0x12
LLKHF_INJECTED = 0x10
VK_V = 0x56
VK_CONTROL, VK_LCONTROL, VK_RCONTROL = 0x11, 0xA2, 0xA3
VK_MENU, VK_LWIN, VK_RWIN = 0x12, 0x5B, 0x5C
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x2
ERROR_ALREADY_EXISTS = 183

# Marks key events that ClipGuard itself injects, so its hook lets them through.
CLIPGUARD_MAGIC = 0xC11B6A2D


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
user32.SetWindowsHookExW.restype = wintypes.HHOOK
user32.CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
user32.CallNextHookEx.restype = LRESULT
user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = wintypes.BOOL
user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short
user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
user32.GetForegroundWindow.restype = wintypes.HWND
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.BringWindowToTop.argtypes = [wintypes.HWND]
user32.IsWindow.argtypes = [wintypes.HWND]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.SendInput.restype = wintypes.UINT
kernel32.GetCurrentThreadId.restype = wintypes.DWORD
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype = wintypes.HANDLE


def clipboard_seq() -> int:
    """Counter that Windows increments every time the clipboard changes."""
    return int(user32.GetClipboardSequenceNumber())


def foreground_window() -> int:
    return user32.GetForegroundWindow() or 0


def window_pid(hwnd: int) -> int:
    pid = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def is_window(hwnd: int) -> bool:
    return bool(hwnd) and bool(user32.IsWindow(hwnd))


def force_foreground(hwnd: int) -> bool:
    """Bring a window to the front, working around Windows' focus-stealing rules.

    Windows only lets the process that owns the foreground window hand focus to
    another one, so we briefly attach our input queue to that window's thread.
    """
    if not is_window(hwnd):
        return False
    fg = foreground_window()
    if fg == hwnd:
        return True
    me = kernel32.GetCurrentThreadId()
    fg_thread = user32.GetWindowThreadProcessId(fg, None) if fg else 0
    attached = bool(fg_thread and fg_thread != me and user32.AttachThreadInput(me, fg_thread, True))
    try:
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
    finally:
        if attached:
            user32.AttachThreadInput(me, fg_thread, False)
    return foreground_window() == hwnd


def send_ctrl_v(extra: int = CLIPGUARD_MAGIC) -> None:
    """Inject Ctrl+V, tagged so ClipGuard's own hook ignores it."""
    def key(vk: int, up: bool) -> INPUT:
        inp = INPUT(type=INPUT_KEYBOARD)
        inp.u.ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=KEYEVENTF_KEYUP if up else 0,
                              time=0, dwExtraInfo=extra)
        return inp

    seq = (INPUT * 4)(key(VK_CONTROL, False), key(VK_V, False),
                      key(VK_V, True), key(VK_CONTROL, True))
    sent = user32.SendInput(4, seq, ctypes.sizeof(INPUT))
    if sent != 4:
        log.warning("SendInput sent %d/4 events (error %d)", sent, ctypes.get_last_error())


_mutex = None


def already_running(name: str = "Local\\ClipGuard.SingleInstance") -> bool:
    """True if another ClipGuard instance holds the named mutex."""
    global _mutex
    _mutex = kernel32.CreateMutexW(None, False, name)
    return ctypes.get_last_error() == ERROR_ALREADY_EXISTS


class PasteHook:
    """Global low-level keyboard hook that can swallow Ctrl+V.

    `should_block(seq)` is called on every physical Ctrl+V with the current
    clipboard sequence number and must return quickly (Windows drops hooks that
    take longer than ~1 s). When it returns True, the keystroke is swallowed and
    `on_blocked(hwnd, seq)` is called with the window that had focus.
    """

    def __init__(self, should_block: Callable[[int], bool],
                 on_blocked: Callable[[int, int], None],
                 allow_injected: bool = False) -> None:
        self.should_block = should_block
        self.on_blocked = on_blocked
        self.allow_injected = allow_injected
        self.ready = threading.Event()
        self.installed = False
        self._thread_id = 0
        self._ctrl_down = False
        self._swallow_v_up = False
        self._proc = HOOKPROC(self._callback)  # keep a reference: ctypes callback
        self._own_pid = os.getpid()

    def start(self) -> bool:
        threading.Thread(target=self._run, name="clipguard-hook", daemon=True).start()
        self.ready.wait(5)
        return self.installed

    def stop(self) -> None:
        if self._thread_id:
            user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)

    def _run(self) -> None:
        self._thread_id = kernel32.GetCurrentThreadId()
        hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._proc,
                                        kernel32.GetModuleHandleW(None), 0)
        self.installed = bool(hook)
        if not hook:
            log.error("Could not install keyboard hook (error %d)", ctypes.get_last_error())
        self.ready.set()
        if not hook:
            return
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            pass
        user32.UnhookWindowsHookEx(hook)

    def _ctrl_held(self) -> bool:
        return self._ctrl_down or bool(user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)

    def _other_modifier_held(self) -> bool:
        return any(user32.GetAsyncKeyState(vk) & 0x8000 for vk in (VK_MENU, VK_LWIN, VK_RWIN))

    def _callback(self, n_code: int, w_param: int, l_param: int) -> int:
        try:
            if n_code == HC_ACTION:
                kb = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                down = w_param in (WM_KEYDOWN, WM_SYSKEYDOWN)
                if kb.vkCode in (VK_CONTROL, VK_LCONTROL, VK_RCONTROL):
                    self._ctrl_down = down
                elif kb.vkCode == VK_V:
                    if down and self._should_swallow(kb):
                        self._swallow_v_up = True
                        self.on_blocked(foreground_window(), clipboard_seq())
                        return 1
                    if not down and self._swallow_v_up:
                        self._swallow_v_up = False
                        return 1
        except Exception:  # never let an exception escape into Windows
            log.exception("keyboard hook error")
        return user32.CallNextHookEx(None, n_code, w_param, l_param)

    def _should_swallow(self, kb: KBDLLHOOKSTRUCT) -> bool:
        if kb.dwExtraInfo == CLIPGUARD_MAGIC:
            return False  # our own injected paste
        if kb.flags & LLKHF_INJECTED and not self.allow_injected:
            return False  # other software typing (e.g. password manager auto-type)
        if not self._ctrl_held() or self._other_modifier_held():
            return False
        if window_pid(foreground_window()) == self._own_pid:
            return False  # pasting inside ClipGuard's own dialog
        return self.should_block(clipboard_seq())
