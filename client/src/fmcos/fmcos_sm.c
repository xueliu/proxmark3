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
// FMCOS Secure Messaging Implementation
//-----------------------------------------------------------------------------

#include "fmcos_sm.h"
#include "fmcos_crypto.h"
#include "ui.h"
#include <string.h>

void fmcos_sm_activate_mac(fmcos_sm_ctx_t *ctx, uint8_t key_id,
                           const uint8_t *mac_key, size_t mac_key_len) {
    if (!ctx || !mac_key) return;
    memset(ctx, 0, sizeof(fmcos_sm_ctx_t));
    ctx->mode = FMCOS_SM_MAC_ONLY;
    ctx->key_id = key_id;
    ctx->mac_key_len = (mac_key_len > 16) ? 16 : mac_key_len;
    memcpy(ctx->mac_key, mac_key, ctx->mac_key_len);
    memset(ctx->iv, 0, 8);
}

void fmcos_sm_activate_enc_mac(fmcos_sm_ctx_t *ctx, uint8_t key_id,
                               const uint8_t *enc_key, size_t enc_key_len,
                               const uint8_t *mac_key, size_t mac_key_len) {
    if (!ctx || !enc_key || !mac_key) return;
    memset(ctx, 0, sizeof(fmcos_sm_ctx_t));
    ctx->mode = FMCOS_SM_ENC_MAC;
    ctx->key_id = key_id;
    ctx->enc_key_len = (enc_key_len > 16) ? 16 : enc_key_len;
    memcpy(ctx->enc_key, enc_key, ctx->enc_key_len);
    ctx->mac_key_len = (mac_key_len > 16) ? 16 : mac_key_len;
    memcpy(ctx->mac_key, mac_key, ctx->mac_key_len);
    memset(ctx->iv, 0, 8);
}

void fmcos_sm_deactivate(fmcos_sm_ctx_t *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(fmcos_sm_ctx_t));
    ctx->mode = FMCOS_SM_NONE;
}

bool fmcos_sm_wrap_command(const fmcos_sm_ctx_t *ctx, fmcos_apdu_t *apdu) {
    if (!ctx || !apdu) return false;
    if (ctx->mode == FMCOS_SM_NONE) return true; // nothing to do

    // Step 1: For ENC_MAC, encrypt the data field first
    uint8_t work_data[256];
    uint16_t work_len = 0;

    if (ctx->mode == FMCOS_SM_ENC_MAC && apdu->has_lc && apdu->lc > 0) {
        // Pad plaintext with 80 00...
        uint8_t padded[256];
        size_t padded_len = 0;
        if (!fmcos_apply_padding(apdu->data, apdu->lc, padded, sizeof(padded), &padded_len)) {
            PrintAndLogEx(ERR, "SM: padding failed");
            return false;
        }
        // Encrypt padded data with enc_key (ECB block-by-block)
        if (!fmcos_encrypt(ctx->enc_key, ctx->enc_key_len, padded, padded_len, work_data)) {
            PrintAndLogEx(ERR, "SM: encryption failed");
            return false;
        }
        work_len = (uint16_t)padded_len;
    } else if (apdu->has_lc && apdu->lc > 0) {
        // MAC_ONLY: data goes through as-is
        memcpy(work_data, apdu->data, apdu->lc);
        work_len = apdu->lc;
    }

    // Step 2: Set CLA bit for SM
    apdu->cla |= 0x04;

    // Step 3: Build MAC input = CLA INS P1 P2 Lc [Data]
    // New Lc = work_len (data or encrypted data) + 4 (MAC)
    uint16_t new_lc = work_len + 4;
    
    uint8_t mac_input[512];
    size_t mac_input_len = 0;
    mac_input[mac_input_len++] = apdu->cla;
    mac_input[mac_input_len++] = apdu->ins;
    mac_input[mac_input_len++] = apdu->p1;
    mac_input[mac_input_len++] = apdu->p2;
    mac_input[mac_input_len++] = (uint8_t)(new_lc & 0xFF);
    if (work_len > 0) {
        memcpy(&mac_input[mac_input_len], work_data, work_len);
        mac_input_len += work_len;
    }

    // Step 4: Compute 4-byte PBOC MAC
    uint8_t mac[4];
    if (!fmcos_generate_mac(ctx->mac_key, ctx->mac_key_len, ctx->iv,
                            mac_input, mac_input_len, mac)) {
        PrintAndLogEx(ERR, "SM: MAC generation failed");
        return false;
    }

    // Step 5: Reassemble APDU: data = [work_data] + MAC(4)
    if (work_len > 0) {
        memcpy(apdu->data, work_data, work_len);
    }
    memcpy(apdu->data + work_len, mac, 4);
    apdu->lc = new_lc;
    apdu->has_lc = true;

    return true;
}

bool fmcos_sm_unwrap_response(const fmcos_sm_ctx_t *ctx, fmcos_resp_t *resp) {
    if (!ctx || !resp) return false;
    if (ctx->mode == FMCOS_SM_NONE) return true;

    // Response must have at least 4 bytes of MAC
    if (resp->data_len < 4) {
        PrintAndLogEx(ERR, "SM: response too short for MAC (%zu bytes)", resp->data_len);
        return false;
    }

    size_t payload_len = resp->data_len - 4;
    uint8_t *resp_mac = &resp->data[payload_len];

    // Verify MAC over payload (or encrypted payload)
    uint8_t computed_mac[4];
    if (!fmcos_generate_mac(ctx->mac_key, ctx->mac_key_len, ctx->iv,
                            resp->data, payload_len, computed_mac)) {
        PrintAndLogEx(ERR, "SM: response MAC computation failed");
        return false;
    }

    if (memcmp(computed_mac, resp_mac, 4) != 0) {
        PrintAndLogEx(ERR, "SM: response MAC mismatch! Expected %02X%02X%02X%02X, got %02X%02X%02X%02X",
                      computed_mac[0], computed_mac[1], computed_mac[2], computed_mac[3],
                      resp_mac[0], resp_mac[1], resp_mac[2], resp_mac[3]);
        return false;
    }

    // For ENC_MAC, decrypt the payload
    if (ctx->mode == FMCOS_SM_ENC_MAC && payload_len > 0) {
        if (payload_len % 8 != 0) {
            PrintAndLogEx(ERR, "SM: encrypted payload not aligned (%zu bytes)", payload_len);
            return false;
        }
        uint8_t decrypted[256];
        if (!fmcos_decrypt(ctx->enc_key, ctx->enc_key_len, resp->data, payload_len, decrypted)) {
            PrintAndLogEx(ERR, "SM: decryption failed");
            return false;
        }
        // Remove 80 00... padding
        size_t real_len = payload_len;
        while (real_len > 0 && decrypted[real_len - 1] == 0x00) {
            real_len--;
        }
        if (real_len > 0 && decrypted[real_len - 1] == 0x80) {
            real_len--; // remove the 0x80 marker
        }
        memcpy(resp->data, decrypted, real_len);
        resp->data_len = real_len;
    } else {
        // MAC_ONLY: just trim the MAC from data
        resp->data_len = payload_len;
    }

    return true;
}
