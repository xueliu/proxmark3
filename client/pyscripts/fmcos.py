#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMCOS 2.0 Smart Card Library for Proxmark3.

This module provides the core FMCOS 2.0 (FM1208/FM1280) smart card
interface classes and utilities. For CLI usage, see fmcos_cli.py.

Classes:
    SimpleDES: Pure Python DES implementation for authentication.
    FMCOS: Main interface class for card communication.

Author: Xue Liu <liuxuenetmail@gmail.com>
License: GPL-3.0
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pm3

# Import logging utilities from fmcos_log module
from fmcos_log import (
    log, log_success, log_error, log_warn, log_debug,
    log_apdu_send, log_apdu_recv, log_raw_output, hex_dump
)

if TYPE_CHECKING:
    pass

# =============================================================================
# Script Metadata
# =============================================================================

__author__ = "Xue Liu <liuxuenetmail@gmail.com>"
__version__ = "1.0.0"
SCRIPT_NAME = "FMCOS"

# =============================================================================
# APDU Constants
# =============================================================================

# Class bytes
CLA_ISO = 0x00
CLA_MAC = 0x04
CLA_PBOC = 0x80
CLA_PBOC_MAC = 0x84
CLA_GAS = 0xE0

# Instruction bytes - ISO/IEC 7816-4 compatible
INS_VERIFY = 0x20
INS_EXTERNAL_AUTH = 0x82
INS_GET_CHALLENGE = 0x84
INS_INTERNAL_AUTH = 0x88
INS_SELECT = 0xA4
INS_READ_BINARY = 0xB0
INS_READ_RECORD = 0xB2
INS_GET_RESPONSE = 0xC0
INS_UPDATE_BINARY = 0xD6
INS_UPDATE_RECORD = 0xDC
INS_APPEND_RECORD = 0xE2

# Instruction bytes - FMCOS proprietary
INS_ERASE_DF = 0x0E
INS_CARD_BLOCK = 0x16
INS_APP_UNBLOCK = 0x18
INS_APP_BLOCK = 0x1E
INS_PIN_UNBLOCK = 0x24
INS_UNBLOCK = 0x2C
INS_INITIALIZE = 0x50
INS_CREDIT_LOAD = 0x52
INS_DEBIT = 0x54
INS_UPDATE_OVERDRAW = 0x58
INS_GET_TRANS_PROVE = 0x5A
INS_GET_BALANCE = 0x5C
INS_RELOAD_PIN = 0x5E
INS_WRITE_KEY = 0xD4
INS_CREATE_FILE = 0xE0

# Status Words
SW_SUCCESS = (0x90, 0x00)
SW_FILE_NOT_FOUND = (0x6A, 0x82)
SW_WRONG_LENGTH = (0x67, 0x00)
SW_SECURITY_NOT_SATISFIED = (0x69, 0x82)
SW_FUNC_NOT_SUPPORTED = (0x6A, 0x81)
SW_CONDITIONS_NOT_SATISFIED = (0x69, 0x85)
SW_WRONG_P1P2 = (0x6A, 0x86)
SW_KEY_NOT_FOUND = (0x6A, 0x88)
SW_DATA_INVALID = (0x6A, 0x80)
SW_FILE_EXISTS = (0x6A, 0x86)
SW_NO_SPACE = (0x6A, 0x84)
SW_INSUFFICIENT_FUNDS = (0x94, 0x01)
SW_MAC_ERROR = (0x93, 0x02)

# Status word descriptions for error reporting
STATUS_WORDS = {
    0x9000: "Success",
    0x6281: "Part of data may be corrupted",
    0x6283: "Selected file invalidated or checksum error",
    0x6300: "Verification failed (no retries left)",
    0x63C0: "Verification failed (0 retries left)",
    0x63C1: "Verification failed (1 retry left)",
    0x63C2: "Verification failed (2 retries left)",
    0x63C3: "Verification failed (3 retries left)",
    0x6400: "State unchanged",
    0x6581: "EEPROM write failed",
    0x6700: "Wrong length",
    0x6900: "CLA incompatible with line protection",
    0x6901: "Invalid state",
    0x6981: "Command incompatible with file structure",
    0x6982: "Security conditions not satisfied",
    0x6983: "Authentication method locked",
    0x6985: "Conditions of use not satisfied",
    0x6987: "No secure messaging",
    0x6988: "Secure messaging data incorrect",
    0x6A80: "Incorrect data field parameters",
    0x6A81: "Function not supported (no MF or card locked)",
    0x6A82: "File not found",
    0x6A83: "Record not found",
    0x6A84: "Not enough space in file",
    0x6A86: "Incorrect P1 P2",
    0x6A88: "Key not found",
    0x6B00: "Offset error (beyond file end)",
    0x6E00: "Invalid CLA",
    0x6F00: "Data invalid",
    0x9302: "MAC error",
    0x9303: "Application permanently locked",
    0x9401: "Insufficient balance",
    0x9403: "Key not found",
    0x9406: "Required MAC not available",
}


# Logging functions imported from fmcos_log

# =============================================================================
# SimplePure Python DES Implementation
# =============================================================================

class SimpleDES:
    """Minimal DES implementation for External Authentication (ECB mode)."""

    _PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 28, 20, 12, 4,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
            61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

    _PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

    _IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

    _E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

    _P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
          2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

    _S = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    _FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
           38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
           36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
           34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

    @staticmethod
    def _permute(block: int, table: list[int], input_size: int) -> int:
        output = 0
        for i, pos in enumerate(table):
            # pos is 1-indexed
            bit = (block >> (input_size - pos)) & 1
            output |= (bit << (len(table) - 1 - i))
        return output

    @classmethod
    def encrypt_block(cls, key: bytes, block: bytes) -> bytes:
        """Encrypt a single 8-byte block using DES ECB."""
        if len(key) != 8 or len(block) != 8:
            raise ValueError("Key and block must be 8 bytes")

        # Key schedule
        k = int.from_bytes(key, 'big')
        k56 = cls._permute(k, cls._PC1, 64)
        subkeys = []
        c, d = (k56 >> 28) & 0xFFFFFFF, k56 & 0xFFFFFFF

        shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        for shift in shifts:
            c = ((c << shift) | (c >> (28 - shift))) & 0xFFFFFFF
            d = ((d << shift) | (d >> (28 - shift))) & 0xFFFFFFF
            cd = (c << 28) | d
            subkeys.append(cls._permute(cd, cls._PC2, 56))

        # Initial Permutation
        msg = int.from_bytes(block, 'big')
        msg = cls._permute(msg, cls._IP, 64)
        l, r = (msg >> 32) & 0xFFFFFFFF, msg & 0xFFFFFFFF

        # Feistel rounds
        for subkey in subkeys:
            new_l = r
            # F-function
            er = cls._permute(r, cls._E, 32)
            er ^= subkey
            
            s_out = 0
            for i in range(8):
                # Extract 6-bit chunk for S-box i
                chunk = (er >> (42 - i * 6)) & 0x3F
                row = ((chunk & 0x20) >> 4) | (chunk & 0x01)
                col = (chunk >> 1) & 0x0F
                
                val = cls._S[i][row][col]
                s_out |= (val << (28 - i * 4))
            
            f_res = cls._permute(s_out, cls._P, 32)
            r = l ^ f_res
            l = new_l

        # Final swap and permutation
        final = (r << 32) | l
        final = cls._permute(final, cls._FP, 64)
        return final.to_bytes(8, 'big')

# =============================================================================
# FMCOS Class - Core Implementation
# =============================================================================

class FMCOS:
    """
    FMCOS 2.0 Smart Card Interface.

    Provides methods for interacting with FMCOS 2.0 (FM1208/FM1280) cards
    via ISO 14443-4 T=CL protocol using the Proxmark3 client.

    Attributes:
        p: Proxmark3 console interface
        debug: Enable debug output
        last_response: Last response data (excluding SW)
        last_sw: Last status word as tuple (SW1, SW2)
    """

    def __init__(self, p: pm3.pm3, *, debug: bool = False):
        """
        Initialize FMCOS interface.

        Args:
            p: Proxmark3 console interface object
            debug: Enable debug output for APDU tracing
        """
        self.p = p
        self.debug = debug
        self.last_response: bytes = b""
        self.last_sw: tuple[int, int] = (0, 0)

    # -------------------------------------------------------------------------
    # Low-Level APDU Communication
    # -------------------------------------------------------------------------

    def send_apdu(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes | None = None,
        le: int | None = None,
        select: bool = True,
    ) -> tuple[bytes, int, int]:
        """
        Send an APDU command and receive response.

        Constructs the APDU based on ISO 7816-4 case structure and sends it
        via `hf 14a apdu` command.

        Args:
            cla: Class byte
            ins: Instruction byte
            p1: Parameter 1
            p2: Parameter 2
            data: Command data (optional)
            le: Expected response length (optional, 0x00 = max)
            select: Whether to select card first (default: True)

        Returns:
            Tuple of (response_data, sw1, sw2)
        """
        # Build APDU header
        apdu = bytes([cla, ins, p1, p2])

        # Add Lc and data if present
        if data:
            apdu += bytes([len(data)]) + data

        # Add Le if present
        if le is not None:
            apdu += bytes([le])

        # Convert to hex string for PM3 command
        apdu_hex = apdu.hex().upper()

        # Send via hf 14a apdu command
        # -s: Select card before sending (if select=True)
        # -k: Keep field on after command
        flags = "-sk" if select else "-k"
        cmd = f"hf 14a apdu {flags} -d {apdu_hex}"

        # Log outgoing APDU
        log_apdu_send(apdu_hex, cmd, debug=self.debug)

        self.p.console(cmd)
        raw_output = self.p.grabbed_output

        # Show raw output in debug mode
        log_raw_output(raw_output, debug=self.debug)

        # Parse response from grabbed output
        response_data = b""
        sw1, sw2 = 0x6F, 0x00  # Default: data invalid (command failed)

        # Look for response in PM3 output
        # PM3 outputs response in format: "<<< XXXXXX" where XXXXXX is hex
        for line in raw_output.split("\n"):
            line = line.strip()

            # Method 1: Look for "<<< " prefix (standard PM3 APDU output)
            if "<<<" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "<<<" and i + 1 < len(parts):
                        hex_part = parts[i + 1]
                        # Validate it's hex
                        if all(c in "0123456789ABCDEFabcdef" for c in hex_part):
                            if len(hex_part) >= 4:  # At least SW1 SW2
                                try:
                                    resp_bytes = bytes.fromhex(hex_part)
                                    if len(resp_bytes) >= 2:
                                        response_data = resp_bytes[:-2]
                                        sw1 = resp_bytes[-2]
                                        sw2 = resp_bytes[-1]
                                except ValueError:
                                    pass
                        break

            # Method 2: Look for "received X bytes" followed by hex data
            # This is a fallback for different PM3 output formats
            elif "received" in line.lower() and "bytes" in line.lower():
                # The hex data might be on this line after ":"
                if ":" in line:
                    hex_part = line.split(":")[-1].strip().replace(" ", "")
                    if all(c in "0123456789ABCDEFabcdef" for c in hex_part):
                        if len(hex_part) >= 4:
                            try:
                                resp_bytes = bytes.fromhex(hex_part)
                                if len(resp_bytes) >= 2:
                                    response_data = resp_bytes[:-2]
                                    sw1 = resp_bytes[-2]
                                    sw2 = resp_bytes[-1]
                            except ValueError:
                                pass

        # Get status word description
        sw_desc = self.get_sw_description(sw1, sw2)

        # Log incoming response
        log_apdu_recv(
            response_data.hex().upper() if response_data else "",
            sw1, sw2, sw_desc,
            debug=self.debug
        )

        # Store last response
        self.last_response = response_data
        self.last_sw = (sw1, sw2)

        return response_data, sw1, sw2

    def check_sw(self, sw1: int, sw2: int, expected: tuple[int, int] = SW_SUCCESS) -> bool:
        """
        Check if status word matches expected value.

        Args:
            sw1: Status word 1
            sw2: Status word 2
            expected: Expected status word tuple (default: 9000)

        Returns:
            True if status word matches expected
        """
        return (sw1, sw2) == expected

    def get_sw_description(self, sw1: int, sw2: int) -> str:
        """
        Get human-readable description for status word.

        Args:
            sw1: Status word 1
            sw2: Status word 2

        Returns:
            Status word description string
        """
        sw = (sw1 << 8) | sw2

        # Check exact match first
        if sw in STATUS_WORDS:
            return STATUS_WORDS[sw]

        # Check for 63Cx pattern (PIN retry counter)
        if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
            retries = sw2 & 0x0F
            return f"Verification failed ({retries} retries left)"

        # Check for 6Cxx pattern (wrong Le)
        if sw1 == 0x6C:
            return f"Wrong Le, expected {sw2} bytes"

        return f"Unknown status: {sw1:02X}{sw2:02X}"

    # -------------------------------------------------------------------------
    # Card Initialization
    # -------------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Connect to card and verify ISO 14443-4 support.

        Returns:
            True if card responds to ISO 14443-4 selection
        """
        log_debug("Connecting to card...", debug=self.debug)

        # Read card info
        self.p.console("hf 14a read")
        output = self.p.grabbed_output

        if "UID" not in output:
            log_error("No card detected")
            return False

        # Check for ISO 14443-4 support
        if "ISO/IEC 14443-4" in output or "RATS" in output:
            log_success("ISO 14443-4 card detected")
            return True

        log_error("Card does not support ISO 14443-4")
        return False

    def disconnect(self) -> None:
        """Disconnect from card (turn off field)."""
        self.p.console("hf 14a raw -c")
        log_debug("Disconnected", debug=self.debug)

    # -------------------------------------------------------------------------
    # File Selection Commands
    # -------------------------------------------------------------------------

    def select_file(self, file_id: int) -> tuple[bytes, bool]:
        """
        Select a file by its 2-byte file identifier.

        SELECT command (00 A4 00 00 02 <FID_H> <FID_L>)

        Args:
            file_id: 2-byte file identifier (e.g., 0x3F00 for MF)

        Returns:
            Tuple of (FCI data, success status)
        """
        fid_bytes = bytes([(file_id >> 8) & 0xFF, file_id & 0xFF])
        data, sw1, sw2 = self.send_apdu(CLA_ISO, INS_SELECT, 0x00, 0x00,
                                         data=fid_bytes, le=0x00)
        return data, self.check_sw(sw1, sw2)

    def select_df(self, df_name: bytes | str) -> tuple[bytes, bool]:
        """
        Select a DF by its name (AID).

        SELECT command (00 A4 04 00 <Len> <DF_Name>)

        Args:
            df_name: DF name as bytes or hex string

        Returns:
            Tuple of (FCI data, success status)
        """
        if isinstance(df_name, str):
            df_name = bytes.fromhex(df_name.replace(" ", ""))

        data, sw1, sw2 = self.send_apdu(CLA_ISO, INS_SELECT, 0x04, 0x00,
                                         data=df_name, le=0x00)
        return data, self.check_sw(sw1, sw2)

    def select_mf(self) -> tuple[bytes, bool]:
        """
        Select the Master File (MF).

        Returns:
            Tuple of (FCI data, success status)
        """
        return self.select_file(0x3F00)

    # -------------------------------------------------------------------------
    # Binary File Commands
    # -------------------------------------------------------------------------

    def read_binary(self, offset: int = 0, length: int = 0,
                    sfi: int | None = None) -> tuple[bytes, bool]:
        """
        Read data from a transparent (binary) EF.

        READ BINARY command (00 B0 <offset_h>/<SFI> <offset_l> <Le>)

        Args:
            offset: Byte offset within file
            length: Number of bytes to read (0 = max available)
            sfi: Short file identifier (optional, uses current file if None)

        Returns:
            Tuple of (read data, success status)
        """
        if sfi is not None:
            # P1 high 3 bits = 100, low 5 bits = SFI
            p1 = 0x80 | (sfi & 0x1F)
            p2 = offset & 0xFF
        else:
            # P1 P2 = offset
            p1 = (offset >> 8) & 0x7F
            p2 = offset & 0xFF

        data, sw1, sw2 = self.send_apdu(CLA_ISO, INS_READ_BINARY, p1, p2,
                                         le=length)
        return data, self.check_sw(sw1, sw2)

    def update_binary(self, offset: int, data: bytes,
                      sfi: int | None = None) -> bool:
        """
        Write data to a transparent (binary) EF.

        UPDATE BINARY command (00 D6 <offset_h>/<SFI> <offset_l> <Lc> <Data>)

        Args:
            offset: Byte offset within file
            data: Data to write
            sfi: Short file identifier (optional, uses current file if None)

        Returns:
            True if write succeeded
        """
        if sfi is not None:
            p1 = 0x80 | (sfi & 0x1F)
            p2 = offset & 0xFF
        else:
            p1 = (offset >> 8) & 0x7F
            p2 = offset & 0xFF

        _, sw1, sw2 = self.send_apdu(CLA_ISO, INS_UPDATE_BINARY, p1, p2,
                                      data=data)
        return self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # Record File Commands
    # -------------------------------------------------------------------------

    def read_record(self, record_num: int, sfi: int | None = None,
                    length: int = 0) -> tuple[bytes, bool]:
        """
        Read a record from a record-oriented EF.

        READ RECORD command (00 B2 <RecNum> <SFI/Mode> <Le>)

        Args:
            record_num: Record number (1-indexed)
            sfi: Short file identifier (optional, uses current file if None)
            length: Expected record length (0 = max)

        Returns:
            Tuple of (record data, success status)
        """
        p1 = record_num

        if sfi is not None:
            # P2 high 5 bits = SFI, low 3 bits = 100 (use record number)
            p2 = ((sfi & 0x1F) << 3) | 0x04
        else:
            # Current file, use record number
            p2 = 0x04

        data, sw1, sw2 = self.send_apdu(CLA_ISO, INS_READ_RECORD, p1, p2,
                                         le=length)
        return data, self.check_sw(sw1, sw2)

    def update_record(self, record_num: int, data: bytes,
                      sfi: int | None = None) -> bool:
        """
        Update a record in a record-oriented EF.

        UPDATE RECORD command (00 DC <RecNum> <SFI/Mode> <Lc> <Data>)

        Args:
            record_num: Record number (1-indexed)
            data: New record data
            sfi: Short file identifier (optional)

        Returns:
            True if update succeeded
        """
        p1 = record_num

        if sfi is not None:
            p2 = ((sfi & 0x1F) << 3) | 0x04
        else:
            p2 = 0x04

        _, sw1, sw2 = self.send_apdu(CLA_ISO, INS_UPDATE_RECORD, p1, p2,
                                      data=data)
        return self.check_sw(sw1, sw2)

    def append_record(self, data: bytes, sfi: int | None = None) -> bool:
        """
        Append a new record to a record-oriented EF.

        APPEND RECORD command (00 E2 00 <SFI/Mode> <Lc> <Data>)

        Args:
            data: Record data to append
            sfi: Short file identifier (optional)

        Returns:
            True if append succeeded
        """
        if sfi is not None:
            p2 = ((sfi & 0x1F) << 3) | 0x00
        else:
            p2 = 0x00

        _, sw1, sw2 = self.send_apdu(CLA_ISO, INS_APPEND_RECORD, 0x00, p2,
                                      data=data)
        return self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # Security Commands
    # -------------------------------------------------------------------------

    def get_challenge(self, length: int = 8) -> tuple[bytes, bool]:
        """
        Request a random number from the card.

        GET CHALLENGE command (00 84 00 00 <Le>)

        Args:
            length: Requested random number length (4 or 8)

        Returns:
            Tuple of (random number, success status)
        """
        if length not in (4, 8):
            length = 8

        data, sw1, sw2 = self.send_apdu(CLA_ISO, INS_GET_CHALLENGE, 0x00, 0x00,
                                         le=length)
        return data, self.check_sw(sw1, sw2)

    def external_auth(self, key_id: int, cryptogram: bytes, select: bool = True) -> bool:
        """
        Perform external authentication.

        EXTERNAL AUTHENTICATE command (00 82 00 <KeyID> 08 <Cryptogram>)

        Must be preceded by GET CHALLENGE. The encrypted_rnd should be
        the card's random number encrypted with the external auth key.

        Args:
            key_id: Key identifier for external auth key (type 39)
            cryptogram: 8-byte encrypted random number
            select: Whether to select card first (default: True)

        Returns:
            True if authentication succeeded
        """
        if len(cryptogram) != 8:
            log_error("Encrypted random number must be 8 bytes")
            return False

        _, sw1, sw2 = self.send_apdu(CLA_ISO, INS_EXTERNAL_AUTH, 0x00, key_id,
                                      data=cryptogram, select=select)
        return self.check_sw(sw1, sw2)

    def internal_auth(self, key_id: int, data: bytes,
                      operation: int = 0x00) -> tuple[bytes, bool]:
        """
        Perform internal authentication / DES operation.

        INTERNAL AUTHENTICATE command (00 88 <Op> <KeyID> <Lc> <Data>)

        Args:
            key_id: DES key identifier
            data: Data for DES operation
            operation: 0x00=encrypt, 0x01=decrypt, 0x02=MAC

        Returns:
            Tuple of (result data, success status)
        """
        resp, sw1, sw2 = self.send_apdu(CLA_ISO, INS_INTERNAL_AUTH, operation,
                                         key_id, data=data)
        return resp, self.check_sw(sw1, sw2)

    def verify_pin(self, key_id: int, pin: bytes | str) -> tuple[int, bool]:
        """
        Verify a PIN/password.

        VERIFY command (00 20 00 <KeyID> <Lc> <PIN>)

        Args:
            key_id: PIN key identifier (type 3A)
            pin: PIN value as bytes or ASCII string

        Returns:
            Tuple of (retries left or -1 if ok, success status)
        """
        if isinstance(pin, str):
            pin = pin.encode("ascii")

        _, sw1, sw2 = self.send_apdu(CLA_ISO, INS_VERIFY, 0x00, key_id,
                                      data=pin)

        if self.check_sw(sw1, sw2):
            return -1, True

        # Check for retry counter in SW2
        if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
            return sw2 & 0x0F, False

        return 0, False

    def write_key(self, key_id: int, key_data: bytes,
                  add_key: bool = True) -> bool:
        """
        Add or modify a key in the key file.

        WRITE KEY command (80 D4 <P1> <KeyID> <Lc> <KeyData>)

        Args:
            key_id: Key identifier
            key_data: Key data including type, permissions, etc.
            add_key: True to add new key (P1=01), False to modify (P1=key type)

        Returns:
            True if operation succeeded
        """
        p1 = 0x01 if add_key else key_data[0]

        _, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_WRITE_KEY, p1, key_id,
                                      data=key_data)
        return self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # File Management Commands
    # -------------------------------------------------------------------------

    def create_file(self, file_id: int, file_info: bytes) -> bool:
        """
        Create a new file (MF/DF/EF).

        CREATE FILE command (80 E0 <ID_H> <ID_L> <Lc> <FileInfo>)

        Args:
            file_id: 2-byte file identifier
            file_info: File control information (type, size, permissions, etc.)

        Returns:
            True if creation succeeded
        """
        p1 = (file_id >> 8) & 0xFF
        p2 = file_id & 0xFF

        _, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_CREATE_FILE, p1, p2,
                                      data=file_info)
        return self.check_sw(sw1, sw2)

    def erase_df(self) -> bool:
        """
        Erase all files under current DF.

        ERASE DF command (80 0E 00 00 00)

        WARNING: This is destructive! Use with caution.

        Returns:
            True if erase succeeded
        """
        _, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_ERASE_DF, 0x00, 0x00,
                                      data=b"")
        return self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # Electronic Purse/Passbook Commands
    # -------------------------------------------------------------------------

    def get_balance(self, app_type: int = 0x02) -> tuple[int, bool]:
        """
        Read electronic purse or passbook balance.

        GET BALANCE command (80 5C 00 <Type> 04)

        Args:
            app_type: 0x01 for e-passbook, 0x02 for e-purse

        Returns:
            Tuple of (balance in cents, success status)
        """
        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_GET_BALANCE, 0x00,
                                         app_type, le=0x04)

        if self.check_sw(sw1, sw2) and len(data) >= 4:
            # Balance is 4 bytes big-endian
            balance = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
            return balance, True

        return 0, False

    def initialize_for_load(self, key_id: int, amount: int,
                            terminal_id: bytes, app_type: int = 0x02
                            ) -> tuple[bytes, bool]:
        """
        Initialize for credit/load transaction.

        INITIALIZE FOR LOAD command (80 50 00 <Type> 0B ...)

        Args:
            key_id: Load key identifier
            amount: Transaction amount in cents
            terminal_id: 6-byte terminal identifier
            app_type: 0x01 for e-passbook, 0x02 for e-purse

        Returns:
            Tuple of (response data, success status)
        """
        if len(terminal_id) != 6:
            log_error("Terminal ID must be 6 bytes")
            return b"", False

        # Build data: key_id(1) + amount(4) + terminal_id(6) = 11 bytes
        cmd_data = bytes([key_id])
        cmd_data += amount.to_bytes(4, "big")
        cmd_data += terminal_id

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_INITIALIZE, 0x00,
                                         app_type, data=cmd_data, le=0x10)
        return data, self.check_sw(sw1, sw2)

    def credit_for_load(self, date: bytes, time: bytes,
                        mac2: bytes) -> tuple[bytes, bool]:
        """
        Complete credit/load transaction.

        CREDIT FOR LOAD command (80 52 00 00 0B ...)

        Args:
            date: 4-byte transaction date (YYYYMMDD BCD)
            time: 3-byte transaction time (HHMMSS BCD)
            mac2: 4-byte MAC2 calculated by host

        Returns:
            Tuple of (TAC, success status)
        """
        if len(date) != 4 or len(time) != 3 or len(mac2) != 4:
            log_error("Invalid parameter lengths")
            return b"", False

        cmd_data = date + time + mac2

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_CREDIT_LOAD, 0x00, 0x00,
                                         data=cmd_data, le=0x04)
        return data, self.check_sw(sw1, sw2)

    def initialize_for_purchase(self, key_id: int, amount: int,
                                terminal_id: bytes, app_type: int = 0x02
                                ) -> tuple[bytes, bool]:
        """
        Initialize for debit/purchase transaction.

        INITIALIZE FOR PURCHASE command (80 50 01 <Type> 0B ...)

        Args:
            key_id: Purchase key identifier
            amount: Transaction amount in cents
            terminal_id: 6-byte terminal identifier
            app_type: 0x01 for e-passbook, 0x02 for e-purse

        Returns:
            Tuple of (response data, success status)
        """
        if len(terminal_id) != 6:
            log_error("Terminal ID must be 6 bytes")
            return b"", False

        cmd_data = bytes([key_id])
        cmd_data += amount.to_bytes(4, "big")
        cmd_data += terminal_id

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_INITIALIZE, 0x01,
                                         app_type, data=cmd_data, le=0x0F)
        return data, self.check_sw(sw1, sw2)

    def debit_for_purchase(self, terminal_seq: bytes, date: bytes,
                           time: bytes, mac1: bytes) -> tuple[bytes, bool]:
        """
        Complete debit/purchase transaction.

        DEBIT FOR PURCHASE command (80 54 01 00 0F ...)

        Args:
            terminal_seq: 4-byte terminal transaction sequence
            date: 4-byte transaction date
            time: 3-byte transaction time
            mac1: 4-byte MAC1 calculated by terminal

        Returns:
            Tuple of (TAC + MAC2, success status)
        """
        if len(terminal_seq) != 4 or len(date) != 4 or len(time) != 3 or len(mac1) != 4:
            log_error("Invalid parameter lengths")
            return b"", False

        cmd_data = terminal_seq + date + time + mac1

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_DEBIT, 0x01, 0x00,
                                         data=cmd_data, le=0x08)
        return data, self.check_sw(sw1, sw2)

    def get_transaction_prove(self, trans_type: int,
                              trans_seq: int) -> tuple[bytes, bool]:
        """
        Retrieve MAC/TAC for transaction recovery.

        GET TRANSACTION PROVE command (80 5A 00 <Type> 02 <Seq>)

        Args:
            trans_type: Transaction type identifier
            trans_seq: 2-byte transaction sequence number

        Returns:
            Tuple of (MAC + TAC, success status)
        """
        seq_bytes = trans_seq.to_bytes(2, "big")

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_GET_TRANS_PROVE, 0x00,
                                         trans_type, data=seq_bytes, le=0x08)
        return data, self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # Application Control Commands
    # -------------------------------------------------------------------------

    def card_block(self, mac: bytes) -> bool:
        """
        Permanently lock the entire card.

        CARD BLOCK command (84 16 00 00 04 <MAC>)

        WARNING: This is PERMANENT and IRREVERSIBLE!

        Args:
            mac: 4-byte MAC calculated with line protection key

        Returns:
            True if card was blocked
        """
        if len(mac) != 4:
            log_error("MAC must be 4 bytes")
            return False

        _, sw1, sw2 = self.send_apdu(CLA_PBOC_MAC, INS_CARD_BLOCK, 0x00, 0x00,
                                      data=mac)
        return self.check_sw(sw1, sw2)

    def application_block(self, mac: bytes, permanent: bool = False) -> bool:
        """
        Lock current application.

        APPLICATION BLOCK command (84 1E 00 <P2> 04 <MAC>)

        Args:
            mac: 4-byte MAC
            permanent: If True, lock is permanent; if False, can be unlocked

        Returns:
            True if application was blocked
        """
        if len(mac) != 4:
            log_error("MAC must be 4 bytes")
            return False

        p2 = 0x01 if permanent else 0x00

        _, sw1, sw2 = self.send_apdu(CLA_PBOC_MAC, INS_APP_BLOCK, 0x00, p2,
                                      data=mac)
        return self.check_sw(sw1, sw2)

    def application_unblock(self, mac: bytes) -> bool:
        """
        Unlock current application.

        APPLICATION UNBLOCK command (84 18 00 00 04 <MAC>)

        Args:
            mac: 4-byte MAC

        Returns:
            True if application was unblocked
        """
        if len(mac) != 4:
            log_error("MAC must be 4 bytes")
            return False

        _, sw1, sw2 = self.send_apdu(CLA_PBOC_MAC, INS_APP_UNBLOCK, 0x00, 0x00,
                                      data=mac)
        return self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # PIN Management Commands
    # -------------------------------------------------------------------------

    def pin_unblock(self, key_id: int, encrypted_pin: bytes, mac: bytes) -> bool:
        """
        Unlock a locked PIN/password.

        PIN UNBLOCK command (84 24 <KeyID> 00 <Lc> <EncryptedPIN> <MAC>)

        Args:
            key_id: PIN key identifier
            encrypted_pin: 8 or 16 byte encrypted PIN (encrypted with line protection key)
            mac: 4-byte MAC

        Returns:
            True if PIN was unblocked
        """
        if len(encrypted_pin) not in (8, 16):
            log_error("Encrypted PIN must be 8 or 16 bytes")
            return False
        if len(mac) != 4:
            log_error("MAC must be 4 bytes")
            return False

        cmd_data = encrypted_pin + mac
        _, sw1, sw2 = self.send_apdu(CLA_PBOC_MAC, INS_PIN_UNBLOCK, key_id, 0x00,
                                      data=cmd_data)
        return self.check_sw(sw1, sw2)

    def reload_pin(self, key_id: int, new_pin: bytes, mac: bytes) -> bool:
        """
        Reload PIN (set new PIN by issuer).

        RELOAD PIN command (80 5E 00 <KeyID> <Lc> <NewPIN> <MAC>)

        Note: MAC is calculated using reload key, not line protection key.

        Args:
            key_id: PIN key identifier
            new_pin: New PIN value (2-6 bytes)
            mac: 4-byte MAC calculated with reload key

        Returns:
            True if PIN was reloaded
        """
        if not 2 <= len(new_pin) <= 6:
            log_error("New PIN must be 2-6 bytes")
            return False
        if len(mac) != 4:
            log_error("MAC must be 4 bytes")
            return False

        cmd_data = new_pin + mac
        _, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_RELOAD_PIN, 0x00, key_id,
                                      data=cmd_data)
        return self.check_sw(sw1, sw2)

    def change_pin(self, key_id: int, old_pin: bytes, new_pin: bytes) -> tuple[int, bool]:
        """
        Change PIN using current PIN verification.

        CHANGE PIN command (80 5E 01 <KeyID> <Lc> <OldPIN> FF <NewPIN>)

        Args:
            key_id: PIN key identifier
            old_pin: Current PIN value (2-6 bytes)
            new_pin: New PIN value (2-6 bytes)

        Returns:
            Tuple of (retries left or -1 if ok, success status)
        """
        if not 2 <= len(old_pin) <= 6:
            log_error("Old PIN must be 2-6 bytes")
            return 0, False
        if not 2 <= len(new_pin) <= 6:
            log_error("New PIN must be 2-6 bytes")
            return 0, False

        # Data format: OldPIN || FF || NewPIN
        cmd_data = old_pin + b'\xFF' + new_pin
        _, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_RELOAD_PIN, 0x01, key_id,
                                      data=cmd_data)

        if self.check_sw(sw1, sw2):
            return -1, True

        # Check for retry counter in SW2
        if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
            return sw2 & 0x0F, False

        return 0, False

    # -------------------------------------------------------------------------
    # E-Passbook Transaction Commands
    # -------------------------------------------------------------------------

    def initialize_for_unload(self, key_id: int, amount: int,
                              terminal_id: bytes) -> tuple[bytes, bool]:
        """
        Initialize for unload/withdrawal transaction (e-passbook).

        INITIALIZE FOR UNLOAD command (80 50 03 01 0B ...)

        Args:
            key_id: Unload key identifier
            amount: Transaction amount in cents
            terminal_id: 6-byte terminal identifier

        Returns:
            Tuple of (response data, success status)
        """
        if len(terminal_id) != 6:
            log_error("Terminal ID must be 6 bytes")
            return b"", False

        # Build data: key_id(1) + amount(4) + terminal_id(6) = 11 bytes
        cmd_data = bytes([key_id])
        cmd_data += amount.to_bytes(4, "big")
        cmd_data += terminal_id

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_INITIALIZE, 0x03, 0x01,
                                         data=cmd_data, le=0x10)
        return data, self.check_sw(sw1, sw2)

    def credit_for_unload(self, date: bytes, time: bytes,
                          mac: bytes) -> tuple[bytes, bool]:
        """
        Complete unload transaction (e-passbook).

        CREDIT FOR UNLOAD command (80 54 03 00 0B ...)

        Args:
            date: 4-byte transaction date (YYYYMMDD BCD)
            time: 3-byte transaction time (HHMMSS BCD)
            mac: 4-byte MAC calculated by host

        Returns:
            Tuple of (TAC, success status)
        """
        if len(date) != 4 or len(time) != 3 or len(mac) != 4:
            log_error("Invalid parameter lengths")
            return b"", False

        cmd_data = date + time + mac

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_DEBIT, 0x03, 0x00,
                                         data=cmd_data, le=0x04)
        return data, self.check_sw(sw1, sw2)

    def initialize_for_cash_withdraw(self, key_id: int, amount: int,
                                     terminal_id: bytes) -> tuple[bytes, bool]:
        """
        Initialize for cash withdrawal transaction (e-passbook).

        INITIALIZE FOR CASH WITHDRAW command (80 50 05 01 0B ...)

        Args:
            key_id: Cash withdraw key identifier
            amount: Transaction amount in cents
            terminal_id: 6-byte terminal identifier

        Returns:
            Tuple of (response data, success status)
        """
        if len(terminal_id) != 6:
            log_error("Terminal ID must be 6 bytes")
            return b"", False

        cmd_data = bytes([key_id])
        cmd_data += amount.to_bytes(4, "big")
        cmd_data += terminal_id

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_INITIALIZE, 0x05, 0x01,
                                         data=cmd_data, le=0x10)
        return data, self.check_sw(sw1, sw2)

    def debit_for_cash_withdraw(self, terminal_seq: bytes, date: bytes,
                                time: bytes, mac1: bytes) -> tuple[bytes, bool]:
        """
        Complete cash withdrawal transaction (e-passbook).

        DEBIT FOR CASH WITHDRAW command (80 54 05 00 0F ...)

        Args:
            terminal_seq: 4-byte terminal transaction sequence
            date: 4-byte transaction date
            time: 3-byte transaction time
            mac1: 4-byte MAC1 calculated by terminal

        Returns:
            Tuple of (TAC + MAC2, success status)
        """
        if len(terminal_seq) != 4 or len(date) != 4 or len(time) != 3 or len(mac1) != 4:
            log_error("Invalid parameter lengths")
            return b"", False

        cmd_data = terminal_seq + date + time + mac1

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_DEBIT, 0x05, 0x00,
                                         data=cmd_data, le=0x08)
        return data, self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # Overdraw Limit Commands
    # -------------------------------------------------------------------------

    def initialize_for_update(self, key_id: int, new_limit: int,
                              terminal_id: bytes) -> tuple[bytes, bool]:
        """
        Initialize for overdraw limit update (e-passbook).

        INITIALIZE FOR UPDATE command (80 50 07 01 0B ...)

        Args:
            key_id: Update key identifier
            new_limit: New overdraw limit in cents
            terminal_id: 6-byte terminal identifier

        Returns:
            Tuple of (response data, success status)
        """
        if len(terminal_id) != 6:
            log_error("Terminal ID must be 6 bytes")
            return b"", False

        cmd_data = bytes([key_id])
        cmd_data += new_limit.to_bytes(4, "big")
        cmd_data += terminal_id

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_INITIALIZE, 0x07, 0x01,
                                         data=cmd_data, le=0x10)
        return data, self.check_sw(sw1, sw2)

    def update_overdraw_limit(self, date: bytes, time: bytes,
                              mac: bytes) -> tuple[bytes, bool]:
        """
        Complete overdraw limit update (e-passbook).

        UPDATE OVERDRAW LIMIT command (80 58 07 01 0B ...)

        Args:
            date: 4-byte transaction date
            time: 3-byte transaction time
            mac: 4-byte MAC

        Returns:
            Tuple of (TAC, success status)
        """
        if len(date) != 4 or len(time) != 3 or len(mac) != 4:
            log_error("Invalid parameter lengths")
            return b"", False

        cmd_data = date + time + mac

        data, sw1, sw2 = self.send_apdu(CLA_PBOC, INS_UPDATE_OVERDRAW, 0x07, 0x01,
                                         data=cmd_data, le=0x04)
        return data, self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # Utility Commands
    # -------------------------------------------------------------------------

    def get_response(self, length: int) -> tuple[bytes, bool]:
        """
        Get response data after SW=61XX.

        GET RESPONSE command (00 C0 00 00 <Le>)

        Args:
            length: Expected response length (from SW2 of previous command)

        Returns:
            Tuple of (response data, success status)
        """
        data, sw1, sw2 = self.send_apdu(CLA_ISO, INS_GET_RESPONSE, 0x00, 0x00,
                                         le=length)
        return data, self.check_sw(sw1, sw2)

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def get_card_info(self) -> dict:
        """
        Read and parse card information.

        Selects MF and returns parsed FCI data.

        Returns:
            Dictionary with card information
        """
        info = {
            "type": "FMCOS 2.0",
            "mf_selected": False,
            "uid": "",
            "atqa": "",
            "sak": "",
        }

        # Get card UID using hf 14a info (more reliable)
        cmd = "hf 14a info"
        log_debug(f"Running: {cmd}", debug=self.debug)
        self.p.console(cmd)
        raw_output = self.p.grabbed_output

        # Show raw output in debug mode
        log_raw_output(raw_output, debug=self.debug)

        for line in raw_output.split("\n"):
            if "UID:" in line:
                # Extract UID, handling different formats
                uid_part = line.split("UID:")[-1].strip()
                uid_part = uid_part.split("[")[0].strip()
                info["uid"] = uid_part
            if "ATQA:" in line:
                atqa_part = line.split("ATQA:")[-1].strip()
                atqa_part = atqa_part.split("[")[0].strip()
                info["atqa"] = atqa_part
            if "SAK:" in line:
                sak_part = line.split("SAK:")[-1].strip()
                sak_part = sak_part.split("[")[0].strip()
                info["sak"] = sak_part
            # Detect if card supports ISO 14443-4
            if "ATS:" in line or "ISO/IEC 14443-4" in line:
                info["iso14443_4"] = True

        # Try to select MF
        fci, success = self.select_mf()
        info["mf_selected"] = success
        if success and fci:
            info["mf_fci"] = fci.hex().upper()

        return info


# =============================================================================
# Module Exports
# =============================================================================

# For CLI interface, use fmcos_cli.py
# Public API: FMCOS, SimpleDES, constants

__all__ = [
    'FMCOS',
    'SimpleDES',
    'SCRIPT_NAME',
    '__version__',
    # APDU Constants
    'CLA_ISO', 'CLA_MAC', 'CLA_PBOC', 'CLA_PBOC_MAC', 'CLA_GAS',
    'INS_VERIFY', 'INS_EXTERNAL_AUTH', 'INS_GET_CHALLENGE', 'INS_INTERNAL_AUTH',
    'INS_SELECT', 'INS_READ_BINARY', 'INS_READ_RECORD', 'INS_GET_RESPONSE',
    'INS_UPDATE_BINARY', 'INS_UPDATE_RECORD', 'INS_APPEND_RECORD',
    'INS_ERASE_DF', 'INS_CARD_BLOCK', 'INS_APP_UNBLOCK', 'INS_APP_BLOCK',
    'INS_PIN_UNBLOCK', 'INS_UNBLOCK', 'INS_INITIALIZE', 'INS_CREDIT_LOAD',
    'INS_DEBIT', 'INS_UPDATE_OVERDRAW', 'INS_GET_TRANS_PROVE', 'INS_GET_BALANCE',
    'INS_RELOAD_PIN', 'INS_WRITE_KEY', 'INS_CREATE_FILE',
    'STATUS_WORDS',
]

