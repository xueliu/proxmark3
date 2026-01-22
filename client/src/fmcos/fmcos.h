//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// High frequency FMCOS (FM1208/FM1280) commands
// FMCOS 2.0 Smart Card OS - ISO 7816-4 compatible
//-----------------------------------------------------------------------------

#ifndef _FMCOS_H_
#define _FMCOS_H_

#include <stdint.h>
#include <stdbool.h>
#include "proxmark3.h"

//-----------------------------------------------------------------------------
// APDU Class Bytes (CLA)
// Standard ISO 7816-4 and PBOC proprietary classes
//-----------------------------------------------------------------------------
#define FMCOS_CLA_ISO       0x00  // Standard ISO 7816-4 commands
#define FMCOS_CLA_MAC       0x04  // Commands with MAC protection
#define FMCOS_CLA_PBOC      0x80  // PBOC proprietary commands
#define FMCOS_CLA_PBOC_MAC  0x84  // PBOC commands with MAC

//-----------------------------------------------------------------------------
// APDU Instruction Bytes (INS)
// ISO 7816-4 standard instructions
//-----------------------------------------------------------------------------
#define FMCOS_INS_VERIFY        0x20  // Verify PIN/password
#define FMCOS_INS_EXT_AUTH      0x82  // External authentication
#define FMCOS_INS_GET_CHALLENGE 0x84  // Get random challenge
#define FMCOS_INS_INT_AUTH      0x88  // Internal authentication
#define FMCOS_INS_SELECT        0xA4  // Select file (DF/EF)
#define FMCOS_INS_READ_BINARY   0xB0  // Read binary data
#define FMCOS_INS_READ_RECORD   0xB2  // Read record data
#define FMCOS_INS_GET_RESPONSE  0xC0  // Get response (for 61XX)
#define FMCOS_INS_UPDATE_BINARY 0xD6  // Update binary data
#define FMCOS_INS_UPDATE_RECORD 0xDC  // Update record data
#define FMCOS_INS_APPEND_RECORD 0xE2  // Append record

//-----------------------------------------------------------------------------
// FMCOS Proprietary Instructions
//-----------------------------------------------------------------------------
#define FMCOS_INS_ERASE_DF      0x0E  // Erase DF and contents
#define FMCOS_INS_WRITE_KEY     0xD4  // Write key to key file
#define FMCOS_INS_CREATE_FILE   0xE0  // Create file (DF/EF)
#define FMCOS_INS_GET_BALANCE   0x5C  // Get e-purse balance
#define FMCOS_INS_INIT_LOAD     0x50  // Initialize for load
#define FMCOS_INS_CREDIT        0x52  // Credit e-purse
#define FMCOS_INS_DEBIT         0x54  // Debit e-purse
#define FMCOS_INS_CHANGE_PIN    0x5E  // Change PIN
#define FMCOS_INS_PIN_UNBLOCK   0x24  // Unblock PIN
#define FMCOS_INS_APP_BLOCK     0x1E  // Block application
#define FMCOS_INS_APP_UNBLOCK   0x18  // Unblock application

//-----------------------------------------------------------------------------
// Key Types (for WRITE KEY command)
//-----------------------------------------------------------------------------
#define FMCOS_KEY_MASTER        0x30  // Card master key
#define FMCOS_KEY_MAINTAIN      0x33  // Card maintain key
#define FMCOS_KEY_APP_MASTER    0x31  // Application master key
#define FMCOS_KEY_APP_MAINTAIN  0x34  // Application maintain key
#define FMCOS_KEY_DES           0x35  // DES/3DES key
#define FMCOS_KEY_PIN           0x3A  // PIN key
#define FMCOS_KEY_EXT_AUTH      0x39  // External auth key

//-----------------------------------------------------------------------------
// File Types (for CREATE FILE command)
//-----------------------------------------------------------------------------
#define FMCOS_FILE_DF           0x38  // Dedicated File (directory)
#define FMCOS_FILE_BINARY       0x28  // Binary Elementary File
#define FMCOS_FILE_FIXED_REC    0x2A  // Fixed-length record EF
#define FMCOS_FILE_VAR_REC      0x2C  // Variable-length record EF
#define FMCOS_FILE_CYCLIC_REC   0x2E  // Cyclic record EF
#define FMCOS_FILE_KEY          0x3F  // Key file
#define FMCOS_FILE_WALLET       0x2F  // E-purse/Wallet file

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t sw1;
    uint8_t sw2;
    uint8_t *data;
    uint16_t len;
} fmcos_resp_t;

// ---------------------------------------------------------------------------
// Prototypes
// ---------------------------------------------------------------------------

// Core
int fmcos_info(void);
int fmcos_send_apdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                    const uint8_t *data, uint16_t len, uint8_t le,
                    uint8_t *resp, uint16_t *resplen, uint8_t *sw1, uint8_t *sw2);

// File Operations
int fmcos_select_file(uint16_t fid, uint8_t *resp, uint16_t *resplen, uint8_t *sw1, uint8_t *sw2);
int fmcos_select_path(const uint8_t *path, uint8_t len, uint8_t *sw1, uint8_t *sw2);
int fmcos_select_df(const uint8_t *aid, uint8_t len, uint8_t *sw1, uint8_t *sw2);
int fmcos_read_binary(uint16_t offset, uint8_t len, uint8_t sfi, uint8_t *out_data, uint8_t *sw1, uint8_t *sw2);
int fmcos_update_binary(uint16_t offset, const uint8_t *data, uint8_t len, uint8_t sfi, uint8_t *sw1, uint8_t *sw2);

// Create functions
int fmcos_create_df(uint16_t fid, uint8_t space, const uint8_t *df_name, uint8_t name_len, const uint8_t *perm, uint8_t *sw1, uint8_t *sw2);
int fmcos_create_key_file(uint8_t slots, const uint8_t *prop, uint8_t *sw1, uint8_t *sw2);
int fmcos_create_binary_ef(uint16_t fid, uint16_t size, const uint8_t *perm, uint8_t *sw1, uint8_t *sw2);
int fmcos_create_record_ef(uint16_t fid, uint8_t rec_type, uint8_t sfi, uint8_t count, uint8_t len, const uint8_t *perm, uint8_t *sw1, uint8_t *sw2);

// Security
int fmcos_get_challenge(uint8_t len, uint8_t *challenge);
int fmcos_ext_auth(uint8_t kid, const uint8_t *key_bytes, uint8_t key_len);
int fmcos_verify_pin(uint8_t kid, const uint8_t *pin, uint8_t len);

// Helpers
const char* fmcos_get_sw_desc(uint8_t sw1, uint8_t sw2);
void fmcos_set_verbose(bool verbose);
void fmcos_drop_field(void);

#endif
