#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMCOS Logging Utilities.

Provides centralized logging functions with color support for the FMCOS
smart card tool. Used by both the core library (fmcos.py) and the CLI
interface (fmcos_cli.py).

Dependencies:
    - Optional: `ansicolors` package for colored output.
      Install with: pip install ansicolors

Example:
    >>> from fmcos_log import log_success, log_error
    >>> log_success("Operation completed")
    [+] Operation completed
    >>> log_error("Something went wrong")
    [!] Something went wrong
"""

from __future__ import annotations

# =============================================================================
# Optional Color Support
# =============================================================================

try:
    from colors import color
except ModuleNotFoundError:
    def color(s: str, fg: str | None = None, bg: str | None = None,
              style: str | None = None) -> str:
        """
        Fallback color function when ansicolors is not installed.

        Args:
            s: The string to colorize.
            fg: Foreground color (ignored).
            bg: Background color (ignored).
            style: Text style (ignored).

        Returns:
            The original string unchanged.
        """
        _ = fg, bg, style
        return str(s)


# =============================================================================
# Logging Functions
# =============================================================================

def log(msg: str = "", prefix: str = "[=]") -> None:
    """
    Print a standard log message with a prefix.

    Args:
        msg: The message to print.
        prefix: The prefix to use (default: "[=]").
    """
    print(f"{prefix} {msg}")


def log_success(msg: str) -> None:
    """
    Print a success message with a green [+] prefix.

    Args:
        msg: The success message to print.
    """
    prefix = f"[{color('+', fg='green')}]"
    print(f"{prefix} {msg}")


def log_error(msg: str) -> None:
    """
    Print an error message with a red [!] prefix.

    Args:
        msg: The error message to print.
    """
    prefix = f"[{color('!', fg='red')}]"
    print(f"{prefix} {msg}")


def log_warn(msg: str) -> None:
    """
    Print a warning message with a yellow [*] prefix.

    Args:
        msg: The warning message to print.
    """
    prefix = f"[{color('*', fg='yellow')}]"
    print(f"{prefix} {msg}")


def log_debug(msg: str, *, debug: bool = False) -> None:
    """
    Print a debug message if debug mode is enabled.

    Args:
        msg: The debug message to print.
        debug: If True, the message will be printed; otherwise ignored.
    """
    if debug:
        prefix = f"[{color('D', fg='cyan')}]"
        print(f"{prefix} {msg}")


def log_apdu_send(apdu_hex: str, cmd: str, *, debug: bool = False) -> None:
    """
    Log an outgoing APDU command with highlighted formatting.

    Args:
        apdu_hex: The APDU as a hex string (e.g., "00A4040007...").
        cmd: The full PM3 command string.
        debug: If True, logs will be printed.
    """
    if debug:
        prefix = f"[{color('>', fg='yellow')}]"
        apdu_colored = color(apdu_hex, fg='yellow')
        print(f"{prefix} PM3 CMD: {color(cmd, fg='cyan')}")
        print(f"{prefix} APDU >>> {apdu_colored}")


def log_apdu_recv(data_hex: str, sw1: int, sw2: int, sw_desc: str,
                  *, debug: bool = False) -> None:
    """
    Log an incoming APDU response with highlighted formatting.

    Args:
        data_hex: The response data as a hex string.
        sw1: Status word byte 1.
        sw2: Status word byte 2.
        sw_desc: Human-readable description of the status word.
        debug: If True, logs will be printed.
    """
    if debug:
        prefix = f"[{color('<', fg='green')}]"
        sw_str = f"{sw1:02X}{sw2:02X}"
        if (sw1, sw2) == (0x90, 0x00):
            sw_colored = color(sw_str, fg='green')
        else:
            sw_colored = color(sw_str, fg='red')
        data_display = data_hex if data_hex else '(empty)'
        print(f"{prefix} APDU <<< {color(data_display, fg='green')} "
              f"SW={sw_colored} ({sw_desc})")


def log_raw_output(output: str, *, debug: bool = False) -> None:
    """
    Log raw Proxmark3 output for debugging purposes.

    Args:
        output: The raw string output from PM3 console.
        debug: If True, logs will be printed.
    """
    if debug:
        prefix = f"[{color('R', fg='magenta')}]"
        print(f"{prefix} --- Raw PM3 Output ---")
        for line in output.split('\n'):
            if line.strip():
                print(f"{prefix} {line}")
        print(f"{prefix} --- End Raw Output ---")


def hex_dump(data: bytes, prefix: str = "    ") -> str:
    """
    Format bytes as a human-readable hex dump string.

    Args:
        data: The bytes to format.
        prefix: A string to prepend to each line (default: 4 spaces).

    Returns:
        A formatted string with hex values and ASCII representation.

    Example:
        >>> hex_dump(b'Hello')
        '    48 65 6C 6C 6F | Hello'
    """
    if not data:
        return f"{prefix}(empty)"
    hex_str = " ".join(f"{b:02X}" for b in data)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{prefix}{hex_str} | {ascii_str}"
