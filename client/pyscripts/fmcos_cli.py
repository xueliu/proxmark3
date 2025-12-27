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

    info = fmcos.get_card_info(keep_field=False)

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
    Select a file by ID.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing file ID.

    Returns:
        0 on success, 1 on failure.
    """
    file_id = int(args.file, 16)
    log(f"Selecting file: {file_id:04X}")

    fci, success = fmcos.select_file(file_id, keep_field=False)

    if success:
        log_success("File selected")
        if fci:
            log(f"FCI: {fci.hex().upper()}")
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

    data, success = fmcos.read_binary(offset, length, sfi, keep_field=False)

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

    if fmcos.update_binary(offset, data, sfi, keep_field=False):
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

    data, success = fmcos.read_record(rec_num, sfi, keep_field=False)

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

    success = fmcos.update_record(record_num, data, sfi, keep_field=False)

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

    challenge, success = fmcos.get_challenge(length, keep_field=False)

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

    retries, success = fmcos.verify_pin(key_id, pin, keep_field=False)

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

    balance, success = fmcos.get_balance(app_type, keep_field=False)

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

    success = fmcos.external_auth(key_id, encrypted_rnd, keep_field=False)

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

    # Step 3: Authenticate (select=False to maintain session, keep_field=False to close)
    success = fmcos.external_auth(key_id, encrypted_rnd, select=False, keep_field=False)

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

    result, success = fmcos.internal_auth(key_id, data, operation=0x00, keep_field=False)

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

    success = fmcos.write_key(key_id, key_data, add_key=True, keep_field=False)

    if success:
        log_success("Key written")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_create(fmcos: FMCOS, args: argparse.Namespace) -> int:
    """
    Create file.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing file ID and file info.

    Returns:
        0 on success, 1 on failure.
    """
    file_id = int(args.file, 16)
    data_hex = args.data

    if not data_hex:
        log_error("File info required (-d)")
        return 1

    try:
        file_info = bytes.fromhex(data_hex)
    except ValueError:
        log_error("Invalid hex data")
        return 1

    log(f"Creating file {file_id:04X}")

    success = fmcos.create_file(file_id, file_info, keep_field=False)

    if success:
        log_success("File created")
        return 0
    else:
        sw1, sw2 = fmcos.last_sw
        log_error(f"Failed: {fmcos.get_sw_description(sw1, sw2)}")
        return 1


def cmd_erase_df(fmcos: FMCOS, _args: argparse.Namespace) -> int:
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

    success = fmcos.erase_df(keep_field=False)

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
    Explore FMCOS file system structure.

    Scans common file ID ranges to find existing files.

    Args:
        fmcos: FMCOS interface instance.
        args: Command line arguments containing target DF.

    Returns:
        0 on success, 1 on failure.
    """
    log(f"{SCRIPT_NAME} v{__version__} - File System Explorer")
    log()

    if args.file != "3F00":
        file_id = int(args.file, 16)
        log(f"Selecting DF: {file_id:04X}")
        _, success = fmcos.select_file(file_id)
        if not success:
            sw1, sw2 = fmcos.last_sw
            log_error(f"Failed to select DF: {fmcos.get_sw_description(sw1, sw2)}")
            return 1
    else:
        log("Exploring MF (3F00)")
        fmcos.select_mf()

    log()
    log("Scanning for files...")
    log()

    found_files = []

    scan_ranges = [
        (0x0001, 0x0020, "EF range 0001-0020"),
        (0xDF01, 0xDF10, "DF range DF01-DF10"),
    ]

    for start, end, desc in scan_ranges:
        log(f"Scanning {desc}...")
        for fid in range(start, end + 1):
            if args.file != "3F00":
                fmcos.select_file(int(args.file, 16))
            else:
                fmcos.select_mf()

            fci, success = fmcos.select_file(fid)
            if success:
                file_type = "Unknown"
                data, bin_ok = fmcos.read_binary(0, 1)
                if bin_ok:
                    file_type = "Binary EF"
                else:
                    data, rec_ok = fmcos.read_record(1)
                    if rec_ok:
                        file_type = "Record EF"
                    else:
                        file_type = "DF or Restricted"

                found_files.append((fid, file_type, fci))
                log_success(f"  Found: {fid:04X} - {file_type}")

    log()
    if found_files:
        log_success(f"Found {len(found_files)} file(s)")
        log()
        log("File Summary:")
        log("-" * 40)
        for fid, ftype, fci in found_files:
            log(f"  {fid:04X}: {ftype}")
            if fci:
                log(f"         FCI: {fci.hex().upper()[:32]}...")
    else:
        log("No files found in scanned ranges")

    return 0


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
  script run fmcos_cli -c info               Display card information
  script run fmcos_cli -c select -f 3F00     Select MF
  script run fmcos_cli -c read_bin -l 16     Read 16 bytes
  script run fmcos_cli -c fast_ext_auth -k 00 -d FFFFFFFFFFFFFFFF  Fast auth
  script run fmcos_cli -c test               Run test suite
  script run fmcos_cli -c explore            Explore file system
        """,
    )

    parser.add_argument(
        "-c", "--command",
        choices=["info", "select", "read_bin", "write_bin", "read_rec", "write_rec",
                 "challenge", "verify", "ext_auth", "int_auth", "fast_ext_auth",
                 "write_key", "create", "erase_df", "balance", "init_load",
                 "init_purchase", "test", "explore"],
        default="info",
        help="Command to execute (default: info)",
    )
    parser.add_argument("-f", "--file", default="3F00", help="File ID in hex")
    parser.add_argument("-o", "--offset", type=int, default=0, help="Byte offset")
    parser.add_argument("-l", "--length", type=int, default=0, help="Bytes to read")
    parser.add_argument("-d", "--data", default="", help="Hex data for write ops")
    parser.add_argument("-r", "--record", type=int, default=1, help="Record number")
    parser.add_argument("-s", "--sfi", type=int, default=None, help="Short File ID")
    parser.add_argument("-k", "--key", default="00", help="Key ID in hex")
    parser.add_argument("-p", "--pin", default="", help="PIN value")
    parser.add_argument("-t", "--type", default="02", help="App type (01/02)")
    parser.add_argument("-a", "--amount", type=int, default=0, help="Transaction amount")
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
    }

    handler = commands.get(args.command, cmd_info)
    return handler(fmcos, args)


if __name__ == "__main__":
    sys.exit(main())
