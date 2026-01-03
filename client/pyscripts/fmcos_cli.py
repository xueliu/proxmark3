#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMCOS 2.0 Smart Card CLI for Proxmark3.

This module provides the command-line interface for interacting with
FMCOS 2.0 (FM1208/FM1280) smart cards.

Usage:
    script run fmcos_cli -c <command> [options]

Examples:
    script run fmcos_cli -c info              # Display card info
    script run fmcos_cli -c select -f 3F00    # Select MF
    script run fmcos_cli -c read_bin -o 0 -l 16  # Read binary file
    script run fmcos_cli -c balance -t 02     # Get e-purse balance

Author: Xue Liu <liuxuenetmail@gmail.com>
License: GPL-3.0
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

import pm3

# Import from our refactored modules
from fmcos import FMCOS, SimpleDES, SCRIPT_NAME, __version__
from fmcos_log import (
    log, log_success, log_error, log_warn, log_debug,
    hex_dump, color
)

if TYPE_CHECKING:
    from collections.abc import Sequence


# =============================================================================
# CLI Command Handlers
# =============================================================================

def cmd_info(fmcos: FMCOS, _args: argparse.Namespace) -> int:
    """
    Display card information.

    Selects MF and displays basic card info including UID, ATQA, SAK.

    Args:
        fmcos: FMCOS interface instance.
        _args: Command line arguments (unused).

    Returns:
        0 on success, 1 on failure.
    """
    log(f"{SCRIPT_NAME} v{__version__} - Card Information")
    log()

    info = fmcos.get_card_info(select=True, keep_field=False)

    log(f"Card Type: {color(info.get('type', 'Unknown'), fg='cyan')}")
    uid = info.get('uid', '')
    if uid:
        log(f"UID: {color(uid, fg='green')}")
    else:
        log(f"UID: {color('Not detected', fg='red')}")

    log(f"ATQA: {info.get('atqa', 'N/A')}")
    log(f"SAK: {info.get('sak', 'N/A')}")

    if info.get("iso14443_4"):
        log_success("Card supports ISO/IEC 14443-4 (required for FMCOS)")
    else:
        log_warn("ISO/IEC 14443-4 support not detected")

    if info.get("mf_selected"):
        log_success("MF (3F00) selected successfully")
        if info.get("mf_fci"):
            log(f"FCI: {color(info.get('mf_fci'), fg='cyan')}")
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed to select MF: {fmcos.get_sw_description(sw1, sw2)}")

    return 0 if info.get("mf_selected") else 1


def cmd_select(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Select a file by file identifier (FID) or by DF name (AID).

    SELECT command supports two modes (per FMCOS 7.4):
    - P1=00: Select by 2-byte file identifier (current directory)
    - P1=04: Select by DF name (application identifier)

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing:
              - file: File ID (hex) or DF name (hex string)
              - name: If True, select by DF name (P1=04)

    Returns:
        0 on success, 1 on failure.
    """
    selector = args.file.replace(" ", "")
    use_name = getattr(args, 'name', False)

    if use_name:
        # Select by DF name (P1=04)
        log(f"Selecting by DF name: {selector}")
        fci, success = fmcos.select_df(selector, select=True, keep_field=False)
    else:
        # Select by file identifier (P1=00)
        try:
            file_id = int(selector, 16)
        except ValueError:
            log_error(f"Invalid file ID: {selector}")
            return 1

        if file_id > 0xFFFF:
            log_error("File ID must be 2 bytes (0000-FFFF)")
            return 1

        log(f"Selecting by file ID: {file_id:04X}")
        fci, success = fmcos.select_file(file_id, select=True, keep_field=False)

    if success:
        log_success("File/DF selected successfully")
        if fci:
            # Parse and display FCI
            parsed = fmcos.parse_fci(fci)
            log(f"FCI (raw): {parsed['raw']}")

            if parsed['df_name']:
                log(f"  DF Name: {color(parsed['df_name'], fg='cyan')}")
                if parsed['df_name'] != parsed['df_name_hex']:
                    log(f"  DF Name (hex): {parsed['df_name_hex']}")

            if parsed['dir_sfi'] is not None:
                log(f"  DIR SFI: {parsed['dir_sfi']:02X}")

            if parsed['issuer_data']:
                log(f"  Issuer Data: {parsed['issuer_data']}")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Selection failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_read_bin(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Read binary file.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing offset, length, SFI.

    Returns:
        0 on success, 1 on failure.
    """
    offset = args.offset
    length = args.length
    sfi = args.sfi

    log(f"Reading binary: offset={offset}, length={length}, SFI={sfi}")

    data, success = fmcos.read_binary(offset, length, sfi, select=True, keep_field=False)

    if success:
        log_success(f"Read {len(data)} bytes:")
        print(hex_dump(data))
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Read failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_write_bin(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Write to binary file.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing offset, data, SFI.

    Returns:
        0 on success, 1 on failure.
    """
    offset = args.offset
    data = bytes.fromhex(args.data.replace(" ", ""))
    sfi = args.sfi

    log(f"Writing binary: offset={offset}, {len(data)} bytes, SFI={sfi}")

    if fmcos.update_binary(offset, data, sfi, select=True, keep_field=False):
        log_success("Write successful")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Write failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_read_rec(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Read record file.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing record number, SFI.

    Returns:
        0 on success, 1 on failure.
    """
    rec_num = args.record
    sfi = args.sfi

    log(f"Reading record: num={rec_num}, SFI={sfi}")

    data, success = fmcos.read_record(rec_num, sfi, select=True, keep_field=False)

    if success:
        log_success(f"Read {len(data)} bytes:")
        print(hex_dump(data))
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Read failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_write_rec(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Write/update record file.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing record number, data, SFI.

    Returns:
        0 on success, 1 on failure.
    """
    record_num = args.record
    sfi = args.sfi
    data_hex = args.data

    if not data_hex:
        log_error("Data required for write operation (-d)")
        return 1

    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        log_error("Invalid hex data")
        return 1

    log(f"Updating record {record_num}, SFI={sfi}, {len(data)} bytes")

    success = fmcos.update_record(record_num, data, sfi, select=True, keep_field=False)

    if success:
        log_success("Record updated")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_challenge(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Get random challenge from card.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing length (4 or 8).

    Returns:
        0 on success, 1 on failure.
    """
    length = args.length if args.length else 8

    if length not in (4, 8):
        log_error("Challenge length must be 4 or 8")
        return 1

    log(f"Requesting {length}-byte challenge...")

    challenge, success = fmcos.get_challenge(length, select=True, keep_field=False)

    if success:
        log_success(f"Challenge: {challenge.hex().upper()}")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_verify(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Verify PIN.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing key ID and PIN.

    Returns:
        0 on success, 1 on failure.
    """
    key_id = int(args.key, 16)
    pin = args.pin

    log(f"Verifying PIN for key {key_id:02X}")

    retries, success = fmcos.verify_pin(key_id, pin, select=True, keep_field=False)

    if success:
        log_success("PIN verified successfully")
        return 0
    else:
        if retries > 0:
            log_error(f"PIN incorrect, {retries} retries left")
        else:
            log_error("PIN locked")
        return 1


def cmd_balance(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Get e-purse or e-passbook balance.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing app type.

    Returns:
        0 on success, 1 on failure.
    """
    app_type = int(args.type, 16)
    app_name = "E-Passbook" if app_type == 0x01 else "E-Purse"

    log(f"Reading {app_name} balance...")

    balance, success = fmcos.get_balance(app_type, select=True, keep_field=False)

    if success:
        yuan = balance // 100
        fen = balance % 100
        log_success(f"Balance: ¥{yuan}.{fen:02d} ({balance} cents)")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_ext_auth(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    External authenticate (requires pre-computed encrypted random).

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing key ID and encrypted data.

    Returns:
        0 on success, 1 on failure.
    """
    key_id = int(args.key, 16)
    data_hex = args.data

    if not data_hex or len(data_hex) != 16:
        log_error("Encrypted random required (8 bytes hex via -d)")
        return 1

    try:
        encrypted_rnd = bytes.fromhex(data_hex)
    except ValueError:
        log_error("Invalid hex data")
        return 1

    log(f"External authenticate with key {key_id:02X}")

    success = fmcos.external_auth(key_id, encrypted_rnd, select=True, keep_field=False)

    if success:
        log_success("External authentication successful")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_fast_ext_auth(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Fast external authentication using pure Python DES.

    Performs complete authentication flow:
    1. Gets 4-byte random challenge from card
    2. Pads to 8 bytes and encrypts with provided key (DES ECB)
    3. Sends encrypted data for authentication

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing key ID and DES key.

    Returns:
        0 on success, 1 on failure.

    Note:
        Only 8-byte keys (Single DES) are supported.
    """
    key_id = int(args.key, 16)
    key_hex = args.data

    if not key_hex:
        log_error("Key required (-d)")
        return 1

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        log_error("Invalid hex key")
        return 1

    if len(key) not in (8, 16):
        log_error("Key must be 8 or 16 bytes")
        return 1

    log(f"Starting fast external auth with KeyID {key_id:02X}...")

    # Step 1: Get 4-byte challenge
    rand, success = fmcos.get_challenge(4)
    if not success:
        log_error("Failed to get challenge")
        return 1
    log(f"  Challenge: {rand.hex().upper()}")

    # Step 2: Encrypt challenge
    # Pad random to 8 bytes: R || 00 00 00 00
    block = rand + b'\x00' * 4

    if len(key) == 16:
        log_error("Only 8-byte keys (Single DES) supported")
        return 1

    try:
        encrypted_rnd = SimpleDES.encrypt_block(key, block)
    except ValueError as e:
        log_error(f"Encryption error: {e}")
        return 1

    log(f"  Encrypted: {encrypted_rnd.hex().upper()}")

    # Step 3: Authenticate (select=False to maintain session)
    # Use args.keep to control whether to keep field on for next command
    keep = getattr(args, 'keep', False)
    success = fmcos.external_auth(key_id, encrypted_rnd, select=False, keep_field=keep)

    if success:
        log_success("External authentication successful")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Auth Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_int_auth(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Internal authenticate / DES operation.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing key ID and data.

    Returns:
        0 on success, 1 on failure.
    """
    key_id = int(args.key, 16)
    data_hex = args.data

    if not data_hex:
        log_error("Data required for DES operation (-d)")
        return 1

    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        log_error("Invalid hex data")
        return 1

    log(f"Internal authenticate with key {key_id:02X}, {len(data)} bytes")

    result, success = fmcos.internal_auth(key_id, data, operation=0x00, select=True, keep_field=False)

    if success:
        log_success(f"Result: {result.hex().upper()}")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_write_key(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Write key to key file.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing key ID and key data.

    Returns:
        0 on success, 1 on failure.
    """
    key_id = int(args.key, 16)
    data_hex = args.data

    if not data_hex:
        log_error("Key data required (-d)")
        return 1

    try:
        key_data = bytes.fromhex(data_hex)
    except ValueError:
        log_error("Invalid hex data")
        return 1

    log(f"Writing key {key_id:02X}, {len(key_data)} bytes")

    keep = getattr(args, 'keep', False)
    no_select = getattr(args, 'no_select', False)
    modify_mode = getattr(args, 'modify', False)
    key_type_arg = getattr(args, 'key_type', None)

    key_type = int(key_type_arg, 16) if key_type_arg else None

    if modify_mode and key_type is None:
        # Try to infer key type from data byte 0 if it looks like a known type
        if len(key_data) > 0 and key_data[0] in [0x39, 0x3A, 0x37, 0x36, 0x38]:
             key_type = key_data[0]
             log(f"Inferred key type {key_type:02X} from data")
        else:
             log_error("Key type required for modification (--key-type)")
             return 1

    success = fmcos.write_key(key_id, key_data, add_key=not modify_mode, key_type=key_type,
                              select=not no_select, keep_field=keep)

    if success:
        log_success("Key written/updated successfully")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_create(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Create a file (DF, EF, Key File, etc.) per FMCOS 7.13.

    File types supported:
    - df: Directory file (requires DF name via -d)
    - binary: Binary/transparent EF
    - fixed: Fixed-length record EF
    - variable: Variable-length record EF
    - cyclic: Cyclic record EF
    - key: Key file
    - raw: Raw file info provided via -d (original behavior)

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments:
              - file: File ID in hex
              - filetype: File type (df, binary, fixed, variable, cyclic, key, raw)
              - data: DF name (for df) or raw file info (for raw)
              - length: File size or record length
              - record: Number of records (for record types)

    Returns:
        0 on success, 1 on failure.
    """
    file_id = int(args.file, 16)
    file_type = getattr(args, 'filetype', 'raw')
    data_hex = args.data
    size = getattr(args, 'length', 256)
    num_records = getattr(args, 'record', 10)

    # Default permissions (free access)
    read_perm = 0x00
    write_perm = 0x00
    create_perm = 0x00
    erase_perm = 0x00

    file_info = None

    if file_type == 'raw':
        # Original behavior: raw file info
        if not data_hex:
            log_error("File info required (-d) for raw file type")
            return 1
        try:
            file_info = bytes.fromhex(data_hex.replace(" ", ""))
        except ValueError:
            log_error("Invalid hex data for file info")
            return 1
        log(f"Creating file {file_id:04X} with raw info")

    elif file_type == 'df':
        # Directory file
        df_name = b""
        if data_hex:
            try:
                df_name = bytes.fromhex(data_hex.replace(" ", ""))
            except ValueError:
                # Try as ASCII
                df_name = data_hex.encode('ascii')

        app_file_id = 0x00
        if size == 0:
            size = 0xFFFF  # Maximum for MF

        file_info = FMCOS.build_file_info_df(
            size=size if size else 0x1000,
            create_perm=create_perm,
            erase_perm=erase_perm,
            app_file_id=app_file_id,
            df_name=df_name
        )
        log(f"Creating DF {file_id:04X}, size={size}, name={df_name.hex() if df_name else 'default'}")

    elif file_type == 'binary':
        # Binary EF
        file_info = FMCOS.build_file_info_binary(
            size=size if size else 256,
            read_perm=read_perm,
            write_perm=write_perm
        )
        log(f"Creating Binary EF {file_id:04X}, size={size}")

    elif file_type in ('fixed', 'variable', 'cyclic'):
        # Record EF
        type_map = {
            'fixed': 0x2A,
            'variable': 0x2C,
            'cyclic': 0x2E,
        }
        record_len = size if size else 32

        file_info = FMCOS.build_file_info_record(
            record_type=type_map[file_type],
            num_records=num_records if num_records >= 2 else 10,
            record_length=record_len,
            read_perm=read_perm,
            write_perm=write_perm
        )
        log(f"Creating {file_type.capitalize()} Record EF {file_id:04X}, "
            f"records={num_records}, length={record_len}")

    elif file_type == 'key':
        # Key file
        num_keys = size if size else 16
        file_info = FMCOS.build_file_info_key(
            num_keys=num_keys,
            df_sfi=0x00,  # DDF
            add_perm=0x00
        )
        log(f"Creating Key File {file_id:04X}, capacity={num_keys} keys")

    else:
        log_error(f"Unknown file type: {file_type}")
        log("Valid types: df, binary, fixed, variable, cyclic, key, raw")
        return 1

    # Display file info being sent
    log(f"File info: {file_info.hex().upper()}")

    keep = getattr(args, 'keep', False)
    no_select = getattr(args, 'no_select', False)
    success = fmcos.create_file(file_id, file_info, select=not no_select, keep_field=keep)

    if success:
        log_success("File created successfully")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_erase_df(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Erase current DF (DANGEROUS!).

    Args:
        fmcos: FMCOS interface instance.
        _args: Command line arguments (unused).

    Returns:
        0 on success, 1 on failure.
    """
    log_warn("WARNING: This will erase all files in current DF!")
    log("Erasing DF...")

    keep = getattr(args, 'keep', False)
    no_select = getattr(args, 'no_select', False)
    success = fmcos.erase_df(select=not no_select, keep_field=keep)

    if success:
        log_success("DF erased")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_init_load(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Initialize for load transaction.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing key ID, amount, type.

    Returns:
        0 on success, 1 on failure.
    """
    key_id = int(args.key, 16)
    app_type = int(args.type, 16)
    amount = args.amount if hasattr(args, 'amount') else 0

    terminal_id = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])

    log(f"Initialize for load: key={key_id:02X}, amount={amount}, type={app_type:02X}")

    resp, success = fmcos.initialize_for_load(key_id, amount, terminal_id, app_type)

    if success:
        log_success(f"Response: {resp.hex().upper()}")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_init_purchase(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Initialize for purchase transaction.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing key ID, amount, type.

    Returns:
        0 on success, 1 on failure.
    """
    key_id = int(args.key, 16)
    app_type = int(args.type, 16)
    amount = args.amount if hasattr(args, 'amount') else 0

    terminal_id = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])

    log(f"Initialize for purchase: key={key_id:02X}, amount={amount}, type={app_type:02X}")

    resp, success = fmcos.initialize_for_purchase(key_id, amount, terminal_id, app_type)

    if success:
        log_success(f"Response: {resp.hex().upper()}")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_test(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Run comprehensive FMCOS card test suite.

    Tests include:
    1. Basic connectivity (SELECT MF, GET CHALLENGE)
    2. File system exploration (enumerate common DFs)
    3. Record/Binary file reading
    4. E-purse/E-passbook detection

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments.

    Returns:
        Number of failed tests.
    """
    log(f"{SCRIPT_NAME} v{__version__} - Comprehensive Test Suite")
    log()

    errors = 0
    passed = 0

    # Test 1: Select MF
    log(f"{color('Test 1:', fg='cyan')} Select MF (3F00)...")
    fci, success = fmcos.select_mf()
    if success:
        log_success("  PASS - MF selected")
        if fci:
            log(f"  FCI: {color(fci.hex().upper(), fg='green')}")
        passed += 1
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"  FAIL - {fmcos.get_sw_description(sw1, sw2)}")
        errors += 1
        log_error("Card may not be FMCOS compatible, stopping tests")
        return errors

    # Test 2: Get 4-byte challenge
    log(f"{color('Test 2:', fg='cyan')} Get 4-byte challenge...")
    challenge, success = fmcos.get_challenge(4)
    if success and len(challenge) == 4:
        log_success(f"  PASS - Random: {color(challenge.hex().upper(), fg='yellow')}")
        passed += 1
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"  FAIL - {fmcos.get_sw_description(sw1, sw2)}")
        errors += 1

    # Test 3: Get 8-byte challenge
    log(f"{color('Test 3:', fg='cyan')} Get 8-byte challenge...")
    challenge, success = fmcos.get_challenge(8)
    if success and len(challenge) == 8:
        log_success(f"  PASS - Random: {color(challenge.hex().upper(), fg='yellow')}")
        passed += 1
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"  FAIL - {fmcos.get_sw_description(sw1, sw2)}")
        errors += 1

    # Test 4: Common DF selections
    log(f"{color('Test 4:', fg='cyan')} Try common DF selections...")
    common_dfs = [
        (0xDF01, "DF01"), (0xDF02, "DF02"), (0xDF03, "DF03"),
        (0xDF04, "DF04"), (0x1001, "1001 (PBOC)"), (0xADF1, "ADF1"),
    ]
    found_dfs = []
    for df_id, desc in common_dfs:
        fmcos.select_mf()
        fci, success = fmcos.select_file(df_id)
        if success:
            log_success(f"  Found: {color(desc, fg='green')}")
            found_dfs.append(df_id)
        else:
            log_debug(f"  Not found: {desc}", debug=args.debug)
    if found_dfs:
        log_success(f"  Found {len(found_dfs)} DF(s)")
    passed += 1

    # Test 5: Common AID selections
    log(f"{color('Test 5:', fg='cyan')} Try common AID selections...")
    common_aids = [
        ("315041592E5359532E4444463031", "1PAY.SYS.DDF01"),
        ("A000000333010101", "PBOC Debit"),
        ("A000000632010105", "T-Union Transit"),
    ]
    fmcos.select_mf()
    found_aids = []
    for aid_hex, desc in common_aids:
        try:
            fci, success = fmcos.select_df(aid_hex)
            if success:
                log_success(f"  Found: {color(desc, fg='green')}")
                found_aids.append(aid_hex)
                fmcos.select_mf()
        except Exception:
            pass
    if found_aids:
        log_success(f"  Found {len(found_aids)} AID(s)")
    passed += 1

    # Test 6-10: Additional tests (simplified)
    log(f"{color('Test 6:', fg='cyan')} Try reading records (SFI 1-10)...")
    if found_dfs:
        fmcos.select_mf()
        fmcos.select_file(found_dfs[0])
    else:
        fmcos.select_mf()
    readable_records = []
    for sfi in range(1, 11):
        data, success = fmcos.read_record(1, sfi=sfi)
        if success and data:
            readable_records.append((sfi, data))
            log_success(f"  SFI {sfi:02d}: {len(data)} bytes")
    passed += 1

    log(f"{color('Test 7:', fg='cyan')} Try reading binary files...")
    readable_bins = []
    for sfi in range(1, 11):
        data, success = fmcos.read_binary(0, 16, sfi=sfi)
        if success and data:
            readable_bins.append((sfi, data))
            log_success(f"  SFI {sfi:02d}: {len(data)} bytes")
    passed += 1

    log(f"{color('Test 8:', fg='cyan')} Try GET BALANCE (e-purse)...")
    fmcos.select_mf()
    balance, success = fmcos.get_balance(0x02)
    if success:
        yuan = balance // 100
        fen = balance % 100
        log_success(f"  E-Purse Balance: {color(f'¥{yuan}.{fen:02d}', fg='green')}")
    else:
        log("  E-purse not found or needs auth")
    passed += 1

    log(f"{color('Test 9:', fg='cyan')} Try INITIALIZE FOR UNLOAD...")
    fmcos.select_mf()
    terminal_id = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
    resp, success = fmcos.initialize_for_unload(0x00, 100, terminal_id)
    if success:
        log_success(f"  E-Passbook found")
    else:
        log("  E-passbook not found or needs auth")
    passed += 1

    log(f"{color('Test 10:', fg='cyan')} Test GET RESPONSE...")
    resp, success = fmcos.get_response(0x10)
    log("  GET RESPONSE tested")
    passed += 1

    # Summary
    log()
    log("=" * 50)
    log(f"Test Results: {color(str(passed), fg='green')} passed, "
        f"{color(str(errors), fg='red')} failed")
    log("=" * 50)

    if errors == 0:
        log_success("All tests completed!")
    else:
        log_error(f"{errors} critical test(s) failed")

    return errors


def cmd_explore(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Explore file system (EF/DF scanner).

    Modes:
    - EF: Scans for Elementary Files (default range 0000-0020)
    - DF: Scans for Dedicated Files (default range DF01-DF10)

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing mode, start, end.

    Returns:
        0 on success, 1 on failure.
    """
    mode = getattr(args, 'mode', 'ef').lower()
    start_arg = getattr(args, 'start', None)
    end_arg = getattr(args, 'end', None)

    # Determine range based on mode and args
    if mode == 'df':
        start_fid = int(start_arg, 16) if start_arg else 0xDF01
        end_fid = int(end_arg, 16) if end_arg else 0xDF10
        range_desc = f"DF Range {start_fid:04X}-{end_fid:04X}"
    else:  # ef default
        start_fid = int(start_arg, 16) if start_arg else 0x0000
        end_fid = int(end_arg, 16) if end_arg else 0x0020
        range_desc = f"EF Range {start_fid:04X}-{end_fid:04X}"

    log(f"Exploring {range_desc}...")

    # Establish initial context (Select Card + Select Base DF)
    base_df = 0x3F00
    if args.file != "3F00":
        base_df = int(args.file, 16)
        log(f"Selecting Base DF: {base_df:04X}")
        _, success = fmcos.select_file(base_df, select=True, keep_field=True)
    else:
        log("Selecting MF (3F00)")
        _, success = fmcos.select_mf(select=True, keep_field=True) # select=True ensures card wake-up

    if not success:
        log_error("Failed to select base DF/MF")
        return 1

    log("-" * 60)
    log(f"{'FID':<6} {'Type':<18} {'Size':<6} {'Name/Info':<30}")
    log("-" * 60)

    found_count = 0

    for fid in range(start_fid, end_fid + 1):
        # Scan by selecting file
        # CRITICAL: Use select=False to maintain session (no WUPA/RATS)
        # keep_field=True keeps RF on
        fci, success = fmcos.select_file(fid, select=False, keep_field=True)

        if success:
            found_count += 1
            fci_hex = fci.hex().upper()
            
            # Parse FCI to get details
            parsed = fmcos.parse_fci(fci)
            
            # Key determination
            f_type = "Unknown"
            size_str = "-"
            info_str = ""
            
            # Identify file type
            is_df = False
            # 1. Check tags
            if '84' in fci_hex or (parsed and parsed.get('df_name')): # DF Name present
                 f_type = "DF"
                 is_df = True
                 name = parsed.get('df_name', '')
                 info_str = f"Name: {name}"
            
            # 2. Check first byte of FCI (Proprietary/FMCOS specific)
            if f_type == "Unknown" and len(fci) > 0:
                type_byte = fci[0]
                if type_byte == 0x38:
                    f_type = "DF"
                    is_df = True
                elif type_byte == 0x28:
                    f_type = "Binary EF"
                elif type_byte in (0x2A, 0x2C, 0x2E):
                    f_type = "Record EF"
                elif type_byte == 0x3F:
                     f_type = "Key File"

            # 3. Probe for EF content if unknown
            # Note: If it's a DF, Read Binary usually fails with 69 86 (No Current EF)
            if f_type == "Unknown":
                 # Try Read Binary (select=False)
                 d, ok = fmcos.read_binary(0, 1, select=False, keep_field=True)
                 if ok:
                     f_type = "Binary EF (Est)"
                 else:
                     sw1, sw2 = fmcos.last_sw
                     # Check for "Condition not satisfied" or "No current EF"
                     # 6986 = Command not allowed (no current EF) -> Likely DF or MF
                     if (sw1, sw2) == (0x69, 0x86):
                         f_type = "DF (Likely)"
                         is_df = True
                     else:
                         # Try Read Record
                         d, ok = fmcos.read_record(1, select=False, keep_field=True)
                         if ok:
                             f_type = "Record EF (Est)"
                         elif fmcos.last_sw == (0x69, 0x86):
                             f_type = "DF (Likely)"
                             is_df = True

            # Extract size
            if parsed and parsed.get('file_size'):
                 size_str = str(parsed['file_size'])
            elif len(fci) >= 3 and fci[0] in [0x28, 0x2A, 0x2C, 0x2E, 0x3F]:
                 size_val = int.from_bytes(fci[1:3], 'big')
                 size_str = str(size_val)
            
            log(f"{fid:04X}   {f_type:<18} {size_str:<6} {info_str:<30}")
            
            # Robust Navigation: Return to Base context if we might have changed it
            # Scan operations (Select) inside a DF changes context to that DF.
            # We MUST reset to base_df to continue scanning the original directory.
            # This mimics the "Select 3F00" seen in trace.
            if is_df or f_type == "Unknown": 
                 # Conservatively reset context if it was a DF or we aren't sure
                 # Actually, standard ISO: Selecting an EF doesn't change DF. Selecting DF does.
                 # So only if is_df is true. But "Likely DF" covers 6986.
                 # Let's always reset context if successful select to be safe like trace?
                 # Trace resets periodically.
                 # Safe approach: Reset context always after a successful find.
                 fmcos.select_file(base_df, select=False, keep_field=True)

    log("-" * 60)
    if found_count == 0:
        log("No files found.")
    else:
        log(f"Total: {found_count} files found.")

    return 0


# =============================================================================
# REPL Mode - Interactive Shell
# =============================================================================

def execute_repl_command(fmcos: FMCOS, cmd: str, args: list[str], debug: bool = False) -> bool:
    """
    Execute a single command in REPL mode.

    Args:
        fmcos: FMCOS interface instance.
        cmd: Command name.
        args: Command arguments.
        debug: Debug mode flag.

    Returns:
        True if command executed successfully, False otherwise.
    """
    try:
        if cmd == "select":
            if not args:
                log_error("Usage: select <fid> [--name]")
                return False
            use_name = "--name" in args
            fid = args[0]
            if use_name:
                fci, success = fmcos.select_df(fid, keep_field=True)
            else:
                fci, success = fmcos.select_file(int(fid, 16), keep_field=True)
            if success:
                log_success(f"Selected: {fid}")
                if fci:
                    log(f"  FCI: {fci.hex().upper()}")
            else:
                sw1, sw2 = fmcos.last_sw
                log_error(f"Select failed: {fmcos.get_sw_description(sw1, sw2)}")
            return success

        elif cmd == "read_bin":
            offset = int(args[0], 0) if args else 0
            length = int(args[1], 0) if len(args) > 1 else 0
            sfi = None
            if "--sfi" in args:
                idx = args.index("--sfi")
                sfi = int(args[idx + 1], 0) if idx + 1 < len(args) else None
            data, success = fmcos.read_binary(offset, length, sfi, keep_field=True)
            if success:
                log_success(f"Read {len(data)} bytes:")
                print(hex_dump(data))
            else:
                sw1, sw2 = fmcos.last_sw
                log_error(f"Read failed: {fmcos.get_sw_description(sw1, sw2)}")
            return success

        elif cmd == "write_bin":
            if len(args) < 2:
                log_error("Usage: write_bin <offset> <hex_data>")
                return False
            offset = int(args[0], 0)
            data = bytes.fromhex(args[1].replace(" ", ""))
            sfi = None
            if "--sfi" in args:
                idx = args.index("--sfi")
                sfi = int(args[idx + 1], 0) if idx + 1 < len(args) else None
            success = fmcos.update_binary(offset, data, sfi, keep_field=True)
            if success:
                log_success(f"Wrote {len(data)} bytes at offset {offset}")
            else:
                sw1, sw2 = fmcos.last_sw
                log_error(f"Write failed: {fmcos.get_sw_description(sw1, sw2)}")
            return success

        elif cmd == "read_rec":
            if not args:
                log_error("Usage: read_rec <record_num> [--sfi N]")
                return False
            rec_num = int(args[0], 0)
            sfi = None
            if "--sfi" in args:
                idx = args.index("--sfi")
                sfi = int(args[idx + 1], 0) if idx + 1 < len(args) else None
            data, success = fmcos.read_record(rec_num, sfi, keep_field=True)
            if success:
                log_success(f"Record {rec_num}: {len(data)} bytes")
                print(hex_dump(data))
            else:
                sw1, sw2 = fmcos.last_sw
                log_error(f"Read record failed: {fmcos.get_sw_description(sw1, sw2)}")
            return success

        elif cmd == "write_rec":
            if len(args) < 2:
                log_error("Usage: write_rec <record_num> <hex_data>")
                return False
            rec_num = int(args[0], 0)
            data = bytes.fromhex(args[1].replace(" ", ""))
            sfi = None
            if "--sfi" in args:
                idx = args.index("--sfi")
                sfi = int(args[idx + 1], 0) if idx + 1 < len(args) else None
            success = fmcos.update_record(rec_num, data, sfi, keep_field=True)
            if success:
                log_success(f"Updated record {rec_num}")
            else:
                sw1, sw2 = fmcos.last_sw
                log_error(f"Write record failed: {fmcos.get_sw_description(sw1, sw2)}")
            return success

        elif cmd == "ext_auth":
            if len(args) < 2:
                log_error("Usage: ext_auth <key_id> <key_hex>")
                return False
            key_id = int(args[0], 16)
            key_hex = args[1].replace(" ", "")
            key_bytes = bytes.fromhex(key_hex)
            # Fast external auth flow
            challenge, ok = fmcos.get_challenge(4, keep_field=True)
            if not ok:
                log_error("Failed to get challenge")
                return False
            padded = challenge + b'\x00' * 4
            des = SimpleDES(key_bytes)
            encrypted = des.encrypt(padded)
            success = fmcos.external_auth(key_id, encrypted, keep_field=True)
            if success:
                log_success(f"External auth with key {key_id:02X} succeeded")
            else:
                sw1, sw2 = fmcos.last_sw
                log_error(f"External auth failed: {fmcos.get_sw_description(sw1, sw2)}")
            return success

        elif cmd == "verify":
            if len(args) < 2:
                log_error("Usage: verify <key_id> <pin>")
                return False
            key_id = int(args[0], 16)
            pin = args[1]
            retries, success = fmcos.verify_pin(key_id, pin, keep_field=True)
            if success:
                log_success("PIN verified")
            else:
                log_error(f"PIN failed, {retries} retries left" if retries > 0 else "PIN locked")
            return success

        elif cmd == "challenge":
            length = int(args[0], 0) if args else 8
            data, success = fmcos.get_challenge(length, keep_field=True)
            if success:
                log_success(f"Challenge: {data.hex().upper()}")
            else:
                sw1, sw2 = fmcos.last_sw
                log_error(f"Get challenge failed: {fmcos.get_sw_description(sw1, sw2)}")
            return success

        elif cmd == "info":
            info = fmcos.get_card_info(keep_field=True)
            log(f"UID: {info.get('uid', 'N/A')}")
            log(f"ATQA: {info.get('atqa', 'N/A')}")
            log(f"SAK: {info.get('sak', 'N/A')}")
            return info.get("mf_selected", False)

        elif cmd == "debug":
            if args and args[0].lower() == "on":
                fmcos.debug = True
                log_success("Debug mode ON")
            elif args and args[0].lower() == "off":
                fmcos.debug = False
                log_success("Debug mode OFF")
            else:
                log(f"Debug mode: {'ON' if fmcos.debug else 'OFF'}")
            return True

        elif cmd == "help":
            log("Available commands:")
            log("  select <fid> [--name]      Select file by FID or DF name")
            log("  read_bin [off] [len]       Read binary file")
            log("  write_bin <off> <data>     Write binary file")
            log("  read_rec <num> [--sfi N]   Read record")
            log("  write_rec <num> <data>     Write record")
            log("  ext_auth <kid> <key>       External authenticate")
            log("  verify <kid> <pin>         Verify PIN")
            log("  challenge [len]            Get random challenge")
            log("  info                       Display card info")
            log("  debug [on|off]             Toggle debug mode")
            log("  reconnect                  Re-select card")
            log("  exit / quit                Exit REPL")
            return True

        elif cmd == "reconnect":
            fci, success = fmcos.select_mf(select=True, keep_field=True)
            if success:
                log_success("Reconnected to card")
            else:
                log_error("Reconnect failed")
            return success

        else:
            log_error(f"Unknown command: {cmd}. Type 'help' for available commands.")
            return False

    except ValueError as e:
        log_error(f"Invalid argument: {e}")
        return False
    except Exception as e:
        log_error(f"Error executing '{cmd}': {e}")
        return False


def cmd_repl(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Interactive REPL mode for multi-command sessions.

    Maintains card session across multiple commands. RF field stays active
    until 'exit' command.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments.

    Returns:
        0 on success, 1 on failure.
    """
    log(f"{SCRIPT_NAME} v{__version__} - Interactive Mode")
    log("Type 'help' for commands, 'exit' to quit")
    log()

    # Warn about RF field timeout
    log_warn("NOTE: PM3 RF field may timeout (~5s) during slow input.")
    log_warn("For authenticated operations, use 'run --script' mode instead.")
    log_warn("Use 'reconnect' command if field drops.")
    log()

    # Initialize session - select card and MF
    fci, success = fmcos.select_mf(select=True, keep_field=True)
    if not success:
        log_error("Failed to initialize card session")
        return 1

    log_success("Card session initialized (MF selected)")
    log()

    while True:
        try:
            line = input("[FMCOS]> ").strip()

            if not line:
                continue

            if line.lower() in ("exit", "quit"):
                log("Releasing RF field...")
                fmcos.disconnect()
                log_success("Goodbye!")
                break

            # Parse command and arguments
            parts = line.split()
            cmd = parts[0].lower()
            cmd_args = parts[1:]

            execute_repl_command(fmcos, cmd, cmd_args, debug=fmcos.debug)

        except KeyboardInterrupt:
            log("\nUse 'exit' to quit")
        except EOFError:
            log("\nEOF detected, exiting...")
            fmcos.disconnect()
            break
        except Exception as e:
            log_error(f"Error: {e}")

    return 0


def cmd_run(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Execute commands from a script file.

    Reads commands from file (one per line), skips comments (#) and empty lines.
    Session is maintained across all commands.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing script file path.

    Returns:
        0 on success, 1 on failure.
    """
    script_file = getattr(args, 'script_file', None)
    if not script_file:
        log_error("Script file required. Use: -c run -f <file>")
        return 1

    try:
        with open(script_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        log_error(f"Script file not found: {script_file}")
        return 1
    except Exception as e:
        log_error(f"Failed to read script file: {e}")
        return 1

    # Filter out empty lines and comments
    commands = []
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if line and not line.startswith('#'):
            commands.append((line_num, line))

    if not commands:
        log_warn("Script file is empty or contains only comments")
        return 0

    log(f"{SCRIPT_NAME} - Executing script: {script_file}")
    log(f"Commands to execute: {len(commands)}")
    log()

    # Initialize session with first command
    fci, success = fmcos.select_mf(select=True, keep_field=True)
    if not success:
        log_error("Failed to initialize card session")
        return 1

    failed = 0
    for i, (line_num, line) in enumerate(commands):
        parts = line.split()
        cmd = parts[0].lower()
        cmd_args = parts[1:]

        log(f"[{i+1}/{len(commands)}] Line {line_num}: {line}")

        success = execute_repl_command(fmcos, cmd, cmd_args, debug=fmcos.debug)
        if not success:
            failed += 1
            log_warn(f"  Command failed, continuing...")

    # Release RF field after all commands
    fmcos.disconnect()

    log()
    if failed == 0:
        log_success(f"Script completed: {len(commands)} commands executed successfully")
    else:
        log_warn(f"Script completed: {len(commands) - failed}/{len(commands)} commands succeeded")

    return 0 if failed == 0 else 1


# =============================================================================
# Argument Parsing
# =============================================================================

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """
    Parse command line arguments.

    Args:
        argv: Command line arguments (defaults to sys.argv).

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="fmcos_cli",
        description=f"{SCRIPT_NAME} v{__version__} - FMCOS 2.0 Smart Card Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  script run fmcos_cli -c info                          Display card information
  script run fmcos_cli -c select -f 3F00                Select MF by FID (P1=00)
  script run fmcos_cli -c select -f A000000003869807 --name   Select ADF by name (P1=04)
  script run fmcos_cli -c read_bin -l 16                Read 16 bytes
  script run fmcos_cli -c create -f 0001 --filetype binary -l 256   Create 256-byte binary EF
  script run fmcos_cli -c create -f DF01 --filetype df -d "MyApp"   Create DF with name
  script run fmcos_cli -c fast_ext_auth -k 00 -d FFFFFFFFFFFFFFFF   Fast auth
  script run fmcos_cli -c repl                          Interactive REPL mode
  script run fmcos_cli -c run --script commands.txt     Execute script file
  script run fmcos_cli -c test                          Run test suite
        """,
    )

    parser.add_argument(
        "-c", "--command",
        choices=["info", "select", "read_bin", "write_bin", "read_rec", "write_rec",
                 "challenge", "verify", "ext_auth", "int_auth", "fast_ext_auth",
                 "write_key", "create", "erase_df", "balance", "init_load",
                 "init_purchase", "test", "explore", "repl", "run"],
        default="info",
        help="Command to execute (default: info)",
    )
    parser.add_argument("--script", dest="script_file",
                        help="Script file for 'run' command (one command per line)")
    parser.add_argument("-f", "--file", default="3F00", help="File ID (hex) or DF name")
    parser.add_argument("-n", "--name", action="store_true",
                        help="Select by DF name (P1=04) instead of file ID (P1=00)")
    parser.add_argument("--filetype", default="raw",
                        choices=["df", "binary", "fixed", "variable", "cyclic", "key", "raw"],
                        help="File type for create command (default: raw)")
    parser.add_argument("-o", "--offset", type=int, default=0, help="Byte offset")
    parser.add_argument("-l", "--length", type=int, default=0, help="File/record size or bytes to read")
    parser.add_argument("-d", "--data", default="", help="Hex data, DF name, or raw file info")
    parser.add_argument("-r", "--record", type=int, default=1, help="Record number or count")
    parser.add_argument("-s", "--sfi", type=int, default=None, help="Short File ID")
    parser.add_argument("-k", "--key", default="00", help="Key ID in hex")
    parser.add_argument("-p", "--pin", default="", help="PIN value")
    parser.add_argument("-t", "--type", default="02", help="App type (01/02)")
    parser.add_argument("-a", "--amount", type=int, default=0, help="Transaction amount")
    parser.add_argument("--keep", action="store_true",
                        help="Keep RF field on after command (for multi-command sessions)")
    parser.add_argument("--no-select", dest="no_select", action="store_true",
                        help="Don't re-select card (use with --keep to maintain auth session)")
    parser.add_argument("--modify", action="store_true", help="Modify existing key (default: Add key)")
    parser.add_argument("--key-type", default=None, help="Key type for modification (hex)")
    
    # Explore arguments
    parser.add_argument("--mode", choices=["ef", "df"], default="ef",
                        help="Explore mode: ef (default) or df")
    parser.add_argument("--start", "-S", help="Start File ID (hex)")
    parser.add_argument("--end", "-E", help="End File ID (hex)")
    
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    return parser.parse_args(argv)


# =============================================================================
# Main Entry Point
# =============================================================================

def main(argv: Sequence[str] | None = None) -> int:
    """
    Main entry point.

    Args:
        argv: Command line arguments (defaults to sys.argv).

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    args = parse_args(argv)

    try:
        p = pm3.pm3()
    except Exception as e:
        log_error(f"Failed to connect to Proxmark3: {e}")
        return 1

    fmcos = FMCOS(p, debug=args.debug)

    commands = {
        "info": cmd_info,
        "select": cmd_select,
        "read_bin": cmd_read_bin,
        "write_bin": cmd_write_bin,
        "read_rec": cmd_read_rec,
        "write_rec": cmd_write_rec,
        "challenge": cmd_challenge,
        "verify": cmd_verify,
        "ext_auth": cmd_ext_auth,
        "fast_ext_auth": cmd_fast_ext_auth,
        "int_auth": cmd_int_auth,
        "write_key": cmd_write_key,
        "create": cmd_create,
        "erase_df": cmd_erase_df,
        "balance": cmd_balance,
        "init_load": cmd_init_load,
        "init_purchase": cmd_init_purchase,
        "test": cmd_test,
        "explore": cmd_explore,
        "repl": cmd_repl,
        "run": cmd_run,
    }

    handler = commands.get(args.command, cmd_info)
    return handler(fmcos, args)


if __name__ == "__main__":
    sys.exit(main())
