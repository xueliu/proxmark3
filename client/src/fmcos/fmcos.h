//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// High frequency FMCOS (FM1208/FM1280) High-Level Commands
//-----------------------------------------------------------------------------

#ifndef _FMCOS_H_
#define _FMCOS_H_

#include <stdint.h>
#include <stdbool.h>
#include "proxmark3.h"
#include "fmcos_core.h"

//-----------------------------------------------------------------------------
// APDU Class Bytes (CLA)
//-----------------------------------------------------------------------------
#define FMCOS_CLA_ISO       0x00
#define FMCOS_CLA_MAC       0x04
#define FMCOS_CLA_PBOC      0x80
#define FMCOS_CLA_PBOC_MAC  0x84

//-----------------------------------------------------------------------------
// APDU Instruction Bytes (INS)
//-----------------------------------------------------------------------------
#define FMCOS_INS_VERIFY        0x20
#define FMCOS_INS_EXT_AUTH      0x82
#define FMCOS_INS_GET_CHALLENGE 0x84
#define FMCOS_INS_INT_AUTH      0x88
#define FMCOS_INS_SELECT        0xA4
#define FMCOS_INS_READ_BINARY   0xB0
#define FMCOS_INS_READ_RECORD   0xB2
#define FMCOS_INS_GET_RESPONSE  0xC0
#define FMCOS_INS_UPDATE_BINARY 0xD6
#define FMCOS_INS_UPDATE_RECORD 0xDC
#define FMCOS_INS_APPEND_RECORD 0xE2

// FMCOS Proprietary Instructions
#define FMCOS_INS_ERASE_DF      0x0E
#define FMCOS_INS_WRITE_KEY     0xD4
#define FMCOS_INS_CREATE_FILE   0xE0
#define FMCOS_INS_GET_BALANCE   0x5C
#define FMCOS_INS_INIT_LOAD     0x50
#define FMCOS_INS_CREDIT        0x52
#define FMCOS_INS_DEBIT         0x54
#define FMCOS_INS_CHANGE_PIN    0x5E
#define FMCOS_INS_PIN_UNBLOCK   0x24
#define FMCOS_INS_APP_BLOCK     0x1E
#define FMCOS_INS_APP_UNBLOCK   0x18

//-----------------------------------------------------------------------------
// File Types
//-----------------------------------------------------------------------------
#define FMCOS_FILE_DF           0x38
#define FMCOS_FILE_BINARY       0x28
#define FMCOS_FILE_FIXED_REC    0x2A
#define FMCOS_FILE_VAR_REC      0x2C
#define FMCOS_FILE_CYCLIC_REC   0x2E
#define FMCOS_FILE_KEY          0x3F
#define FMCOS_FILE_WALLET       0x2F

// ---------------------------------------------------------------------------
// Prototypes
// ---------------------------------------------------------------------------

// Core
int fmcos_info(fmcos_session_t *session);

// File Operations
int fmcos_cmd_select_file(fmcos_session_t *session, uint16_t fid, fmcos_resp_t *resp);
int fmcos_cmd_select_df(fmcos_session_t *session, const uint8_t *aid, uint8_t len, fmcos_resp_t *resp);
int fmcos_cmd_read_binary(fmcos_session_t *session, uint16_t offset, uint8_t len, uint8_t sfi, fmcos_resp_t *resp);
int fmcos_cmd_read_record(fmcos_session_t *session, uint8_t rec_num, uint8_t sfi, fmcos_resp_t *resp);
int fmcos_cmd_update_binary(fmcos_session_t *session, uint16_t offset, const uint8_t *data, uint8_t len, uint8_t sfi, fmcos_resp_t *resp);
int fmcos_cmd_get_balance(fmcos_session_t *session, uint8_t app_type, uint32_t *balance);

// Create functions
int fmcos_cmd_create_df(fmcos_session_t *session, uint16_t fid, uint8_t space, const uint8_t *df_name, uint8_t name_len, const uint8_t *perm, fmcos_resp_t *resp);
int fmcos_cmd_create_key_file(fmcos_session_t *session, uint8_t slots, const uint8_t *prop, fmcos_resp_t *resp);
int fmcos_cmd_create_binary_ef(fmcos_session_t *session, uint16_t fid, uint16_t size, const uint8_t *perm, fmcos_resp_t *resp);
int fmcos_cmd_create_record_ef(fmcos_session_t *session, uint16_t fid, uint8_t rec_type, uint8_t sfi, uint8_t count, uint8_t len, const uint8_t *perm, fmcos_resp_t *resp);

// Security
int fmcos_cmd_get_challenge(fmcos_session_t *session, uint8_t len, fmcos_resp_t *resp);
int fmcos_cmd_ext_auth(fmcos_session_t *session, uint8_t kid, const uint8_t *key_bytes, uint8_t key_len, fmcos_resp_t *resp);
int fmcos_cmd_verify_pin(fmcos_session_t *session, uint8_t kid, const uint8_t *pin, uint8_t len, fmcos_resp_t *resp);

// Extended Security (Proprietary / Lock / PIN / Key commands)
int fmcos_cmd_change_pin(fmcos_session_t *session, uint8_t kid, const uint8_t *old_pin, const uint8_t *new_pin, uint8_t pin_len, fmcos_resp_t *resp);
int fmcos_cmd_reload_pin(fmcos_session_t *session, uint8_t pin_kid, const uint8_t *new_pin, uint8_t pin_len, const uint8_t *maint_key, size_t maint_key_len, fmcos_resp_t *resp);
int fmcos_cmd_pin_unblock(fmcos_session_t *session, uint8_t pin_kid, const uint8_t *new_pin, uint8_t pin_len, const uint8_t *unblock_key, size_t key_len, fmcos_resp_t *resp);
int fmcos_cmd_write_key(fmcos_session_t *session, uint8_t is_add, uint8_t key_type, uint8_t key_id, const uint8_t *key_data, uint8_t key_data_len, fmcos_resp_t *resp);
int fmcos_cmd_card_block(fmcos_session_t *session, const uint8_t *maint_key, size_t key_len, fmcos_resp_t *resp);
int fmcos_cmd_app_block(fmcos_session_t *session, uint8_t is_permanent, const uint8_t *maint_key, size_t key_len, fmcos_resp_t *resp);
int fmcos_cmd_app_unblock(fmcos_session_t *session, const uint8_t *maint_key, size_t key_len, fmcos_resp_t *resp);

#endif

