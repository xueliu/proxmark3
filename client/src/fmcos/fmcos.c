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
// High frequency FMCOS (FM1208/FM1280) High-Level Commands Implementation
//-----------------------------------------------------------------------------

#include "fmcos.h"
#include "fmcos_crypto.h"
#include "fmcos_status.h"
#include "cmdtrace.h"
#include "pm3_binlib.h"
#include "pm3_cmd.h"
#include "ui.h"
#include <string.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// File Operations
// ---------------------------------------------------------------------------

int fmcos_cmd_select_file(fmcos_session_t *session, uint16_t fid, fmcos_resp_t *resp) {
    fmcos_apdu_t req;
    uint8_t data[2] = {fid >> 8, fid & 0xFF};
    fmcos_apdu_build_case3(&req, FMCOS_CLA_ISO, FMCOS_INS_SELECT, 0x00, 0x00, data, 2);
    // When Le=0 is required for FCI:
    req.has_le = true;
    req.le = 0x00;
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_select_df(fmcos_session_t *session, const uint8_t *aid, uint8_t len, fmcos_resp_t *resp) {
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_ISO, FMCOS_INS_SELECT, 0x04, 0x00, aid, len);
    req.has_le = true;
    req.le = 0x00;
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_read_binary(fmcos_session_t *session, uint16_t offset, uint8_t len, uint8_t sfi, fmcos_resp_t *resp) {
    fmcos_apdu_t req;
    uint8_t p1, p2;
    if (sfi) {
        p1 = 0x80 | (sfi & 0x1F);
        p2 = offset & 0xFF;
    } else {
        p1 = (offset >> 8) & 0x7F;
        p2 = offset & 0xFF;
    }
    fmcos_apdu_build_case2(&req, FMCOS_CLA_ISO, FMCOS_INS_READ_BINARY, p1, p2, len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_update_binary(fmcos_session_t *session, uint16_t offset, const uint8_t *data, uint8_t len, uint8_t sfi, fmcos_resp_t *resp) {
    fmcos_apdu_t req;
    uint8_t p1, p2;
    if (sfi) {
        p1 = 0x80 | (sfi & 0x1F);
        p2 = offset & 0xFF;
    } else {
        p1 = (offset >> 8) & 0x7F;
        p2 = offset & 0xFF;
    }
    fmcos_apdu_build_case3(&req, FMCOS_CLA_ISO, FMCOS_INS_UPDATE_BINARY, p1, p2, data, len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_read_record(fmcos_session_t *session, uint8_t rec_num, uint8_t sfi, fmcos_resp_t *resp) {
    fmcos_apdu_t req;
    uint8_t p2;
    if (sfi) {
        p2 = (sfi << 3) | 0x04;
    } else {
        p2 = 0x04;
    }
    fmcos_apdu_build_case2(&req, FMCOS_CLA_ISO, FMCOS_INS_READ_RECORD, rec_num, p2, 0x00);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_get_balance(fmcos_session_t *session, uint8_t app_type, uint32_t *balance) {
    fmcos_apdu_t req;
    fmcos_resp_t resp;
    fmcos_apdu_build_case2(&req, FMCOS_CLA_PBOC, FMCOS_INS_GET_BALANCE, 0x00, app_type, 0x04);
    int ret = fmcos_exchange_apdu(session, &req, &resp);
    
    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2) && resp.data_len >= 4) {
        *balance = (resp.data[0] << 24) | (resp.data[1] << 16) | (resp.data[2] << 8) | resp.data[3];
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

int fmcos_cmd_get_challenge(fmcos_session_t *session, uint8_t len, fmcos_resp_t *resp) {
    fmcos_apdu_t req;
    fmcos_apdu_build_case2(&req, FMCOS_CLA_ISO, FMCOS_INS_GET_CHALLENGE, 0x00, 0x00, len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_ext_auth(fmcos_session_t *session, uint8_t kid, const uint8_t *key_bytes, uint8_t key_len, fmcos_resp_t *resp) {
    if (!key_bytes || (key_len != 8 && key_len != 16)) return PM3_EINVARG;
    
    fmcos_resp_t cha_resp;
    int ret = fmcos_cmd_get_challenge(session, 8, &cha_resp);
    if (ret != PM3_SUCCESS) return ret;
    if (!fmcos_status_is_ok(cha_resp.sw1, cha_resp.sw2) || cha_resp.data_len < 8) return PM3_EIO;

    uint8_t cryptogram[8];
    if (!fmcos_encrypt(key_bytes, key_len, cha_resp.data, 8, cryptogram)) {
        return PM3_EIO;
    }

    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_ISO, FMCOS_INS_EXT_AUTH, kid, 0x00, cryptogram, 8);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_verify_pin(fmcos_session_t *session, uint8_t kid, const uint8_t *pin, uint8_t len, fmcos_resp_t *resp) {
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_ISO, FMCOS_INS_VERIFY, 0x00, kid, pin, len);
    return fmcos_exchange_apdu(session, &req, resp);
}

// ---------------------------------------------------------------------------
// Create Functions
// ---------------------------------------------------------------------------

int fmcos_cmd_create_df(fmcos_session_t *session, uint16_t fid, uint8_t space, const uint8_t *df_name, uint8_t name_len, const uint8_t *perm, fmcos_resp_t *resp) {
    uint8_t data[32];
    uint8_t data_len = 0;
    
    const uint8_t default_perm[5] = {0xF0, 0xF0, 0x95, 0xFF, 0xFF};
    const uint8_t *use_perm = perm ? perm : default_perm;
    
    data[data_len++] = FMCOS_FILE_DF;  // 0x38
    data[data_len++] = space;          // space byte
    data[data_len++] = 0x00;           // reserved
    memcpy(data + data_len, use_perm, 5);
    data_len += 5;
    if (df_name && name_len > 0) {
        memcpy(data + data_len, df_name, name_len);
        data_len += name_len;
    }
    
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, (fid >> 8) & 0xFF, fid & 0xFF, data, data_len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_create_key_file(fmcos_session_t *session, uint8_t slots, const uint8_t *prop, fmcos_resp_t *resp) {
    uint8_t data[16];
    uint8_t data_len = 0;
    
    const uint8_t default_prop[5] = {0x8F, 0x95, 0xF0, 0xFF, 0xFF};
    const uint8_t *use_prop = prop ? prop : default_prop;
    
    data[data_len++] = FMCOS_FILE_KEY;  // 0x3F
    data[data_len++] = slots;           // single byte slots
    memcpy(data + data_len, use_prop, 5);
    data_len += 5;
    
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, 0x00, 0x00, data, data_len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_create_binary_ef(fmcos_session_t *session, uint16_t fid, uint16_t size, const uint8_t *perm, fmcos_resp_t *resp) {
    uint8_t data[16];
    uint8_t data_len = 0;
    
    const uint8_t default_perm[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t *use_perm = perm ? perm : default_perm;
    
    data[data_len++] = FMCOS_FILE_BINARY;  // 0x28
    data[data_len++] = (size >> 8) & 0xFF;
    data[data_len++] = size & 0xFF;
    memcpy(data + data_len, use_perm, 5);
    data_len += 5;
    
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, (fid >> 8) & 0xFF, fid & 0xFF, data, data_len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_create_record_ef(fmcos_session_t *session, uint16_t fid, uint8_t rec_type, uint8_t sfi, uint8_t count, uint8_t len, const uint8_t *perm, fmcos_resp_t *resp) {
    uint8_t data[16];
    uint8_t data_len = 0;
    
    const uint8_t default_perm[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t *use_perm = perm ? perm : default_perm;
    
    data[data_len++] = rec_type;
    data[data_len++] = sfi;
    data[data_len++] = count;
    data[data_len++] = len;
    memcpy(data + data_len, use_perm, 5);
    data_len += 5;
    
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, (fid >> 8) & 0xFF, fid & 0xFF, data, data_len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_info(fmcos_session_t *session) {
    fmcos_resp_t resp;
    PrintAndLogEx(INFO, "Selecting MF (3F00)...");
    
    int ret = fmcos_cmd_select_file(session, 0x3F00, &resp);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Comms failed");
        return ret;
    }
    
    PrintAndLogEx(INFO, "Select SW: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
    
    if (fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        PrintAndLogEx(INFO, "FCI Length: %d", resp.data_len);
        char hex[512] = {0};
        for(size_t i=0; i<resp.data_len; i++) snprintf(hex+i*2, sizeof(hex)-i*2, "%02X", resp.data[i]);
        PrintAndLogEx(INFO, "FCI: %s", hex);
    }
    
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// Extended Security / Proprietary Commands
// ---------------------------------------------------------------------------

int fmcos_cmd_change_pin(fmcos_session_t *session, uint8_t kid, const uint8_t *old_pin, const uint8_t *new_pin, uint8_t pin_len, fmcos_resp_t *resp) {
    if (!session || !old_pin || !new_pin || pin_len == 0) return PM3_EINVARG;

    uint8_t data[256];
    uint8_t data_len = 0;
    
    memcpy(data, old_pin, pin_len);
    data_len += pin_len;
    data[data_len++] = 0xFF; // Separator
    memcpy(data + data_len, new_pin, pin_len);
    data_len += pin_len;

    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_CHANGE_PIN, 0x01, kid, data, data_len);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_reload_pin(fmcos_session_t *session, uint8_t pin_kid, const uint8_t *new_pin, uint8_t pin_len, const uint8_t *maint_key, size_t maint_key_len, fmcos_resp_t *resp) {
    if (!session || !new_pin || pin_len == 0 || !maint_key || maint_key_len < 8) return PM3_EINVARG;

    // Derived MAC key: XOR the first 8 bytes and second 8 bytes of the maintenance key
    uint8_t derived_key[8];
    memcpy(derived_key, maint_key, 8);
    if (maint_key_len >= 16) {
        for (int i=0; i<8; i++) {
            derived_key[i] ^= maint_key[8+i];
        }
    }

    // Input for MAC is just the new PIN
    uint8_t mac[4];
    if (!fmcos_generate_mac(derived_key, 8, NULL, new_pin, pin_len, mac)) {
        return PM3_EIO;
    }

    uint8_t data[256];
    memcpy(data, new_pin, pin_len);
    memcpy(data + pin_len, mac, 4);

    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_CHANGE_PIN, 0x00, pin_kid, data, pin_len + 4);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_pin_unblock(fmcos_session_t *session, uint8_t pin_kid, const uint8_t *new_pin, uint8_t pin_len, const uint8_t *unblock_key, size_t key_len, fmcos_resp_t *resp) {
    if (!session || !new_pin || pin_len == 0 || !unblock_key) return PM3_EINVARG;

    // MAC input: 84 24 pin_kid 00 Lc ENC_PIN
    // Note: SM handles secure messaging wrapping. However for specific commands it might be 
    // better to construct it manually if it doesn't follow the session's overall state.
    // For now we will construct it manually since it uses standard PBOC MAC.
    
    // 1. Pad and encrypt new PIN
    uint8_t padded_pin[256];
    size_t padded_len = 0;
    if (!fmcos_apply_padding(new_pin, pin_len, padded_pin, sizeof(padded_pin), &padded_len)) {
        return PM3_EIO;
    }
    
    uint8_t enc_pin[256];
    if (!fmcos_encrypt(unblock_key, key_len, padded_pin, padded_len, enc_pin)) {
        return PM3_EIO;
    }

    // 2. Calculate MAC
    uint8_t mac_input[256];
    mac_input[0] = FMCOS_CLA_PBOC_MAC;
    mac_input[1] = FMCOS_INS_PIN_UNBLOCK;
    mac_input[2] = pin_kid;
    mac_input[3] = 0x00;
    mac_input[4] = padded_len + 4;
    memcpy(mac_input + 5, enc_pin, padded_len);

    uint8_t mac[4];
    if (!fmcos_generate_mac(unblock_key, key_len, NULL, mac_input, padded_len + 5, mac)) {
        return PM3_EIO;
    }

    // 3. Assemble payload
    uint8_t payload[256];
    memcpy(payload, enc_pin, padded_len);
    memcpy(payload + padded_len, mac, 4);

    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC_MAC, FMCOS_INS_PIN_UNBLOCK, pin_kid, 0x00, payload, padded_len + 4);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_write_key(fmcos_session_t *session, uint8_t is_add, uint8_t key_type, uint8_t key_id, const uint8_t *key_data, uint8_t key_data_len, fmcos_resp_t *resp) {
    if (!session || !key_data) return PM3_EINVARG;

    fmcos_apdu_t req;
    // For basic write_key, depends if SM is active.
    // If SM is active, core will wrap it. 
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_WRITE_KEY, is_add ? 0x00 : 0x01, key_id, key_data, key_data_len);
    // Real implementation usually needs to add key_type into the payload or P1/P2 based on exact manual
    // Assuming simple payload for now
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_card_block(fmcos_session_t *session, const uint8_t *maint_key, size_t key_len, fmcos_resp_t *resp) {
    if (!session || !maint_key) return PM3_EINVARG;

    uint8_t mac_input[5] = {FMCOS_CLA_PBOC_MAC, FMCOS_INS_APP_BLOCK - 0x08, 0x00, 0x00, 0x04}; // 84 16 00 00 04
    uint8_t mac[4];
    if (!fmcos_generate_mac(maint_key, key_len, NULL, mac_input, 5, mac)) {
        return PM3_EIO;
    }
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC_MAC, 0x16, 0x00, 0x00, mac, 4);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_app_block(fmcos_session_t *session, uint8_t is_permanent, const uint8_t *maint_key, size_t key_len, fmcos_resp_t *resp) {
    if (!session || !maint_key) return PM3_EINVARG;

    uint8_t p2 = is_permanent ? 0x01 : 0x00;
    uint8_t mac_input[5] = {FMCOS_CLA_PBOC_MAC, FMCOS_INS_APP_BLOCK, 0x00, p2, 0x04}; // 84 1E 00 P2 04
    uint8_t mac[4];
    if (!fmcos_generate_mac(maint_key, key_len, NULL, mac_input, 5, mac)) {
        return PM3_EIO;
    }
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC_MAC, FMCOS_INS_APP_BLOCK, 0x00, p2, mac, 4);
    return fmcos_exchange_apdu(session, &req, resp);
}

int fmcos_cmd_app_unblock(fmcos_session_t *session, const uint8_t *maint_key, size_t key_len, fmcos_resp_t *resp) {
    if (!session || !maint_key) return PM3_EINVARG;

    uint8_t mac_input[5] = {FMCOS_CLA_PBOC_MAC, FMCOS_INS_APP_UNBLOCK, 0x00, 0x00, 0x04}; // 84 18 00 00 04
    uint8_t mac[4];
    if (!fmcos_generate_mac(maint_key, key_len, NULL, mac_input, 5, mac)) {
        return PM3_EIO;
    }
    fmcos_apdu_t req;
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC_MAC, FMCOS_INS_APP_UNBLOCK, 0x00, 0x00, mac, 4);
    return fmcos_exchange_apdu(session, &req, resp);
}
