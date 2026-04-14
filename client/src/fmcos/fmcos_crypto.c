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
// FMCOS Cryptography Implementation
//-----------------------------------------------------------------------------

#include "fmcos_crypto.h"
#include "mbedtls/des.h"
#include <string.h>

bool fmcos_apply_padding(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max_len, size_t *out_len) {
    if (!in && in_len > 0) return false;
    if (!out || !out_len) return false;

    size_t required_len = in_len + 8 - (in_len % 8);
    if (required_len > out_max_len) return false;

    if (in_len > 0 && in != out) {
        memcpy(out, in, in_len);
    }

    out[in_len] = 0x80;
    for (size_t i = in_len + 1; i < required_len; i++) {
        out[i] = 0x00;
    }

    *out_len = required_len;
    return true;
}

bool fmcos_encrypt(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len, uint8_t *output) {
    if (!key || !input || !output || input_len % 8 != 0) return false;

    if (key_len == 8) {
        mbedtls_des_context ctx;
        mbedtls_des_init(&ctx);
        mbedtls_des_setkey_enc(&ctx, key);
        for (size_t i = 0; i < input_len; i += 8) {
            mbedtls_des_crypt_ecb(&ctx, &input[i], &output[i]);
        }
        mbedtls_des_free(&ctx);
        return true;
    } else if (key_len == 16) {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        mbedtls_des3_set2key_enc(&ctx, key);
        for (size_t i = 0; i < input_len; i += 8) {
            mbedtls_des3_crypt_ecb(&ctx, &input[i], &output[i]);
        }
        mbedtls_des3_free(&ctx);
        return true;
    }
    return false;
}

bool fmcos_decrypt(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len, uint8_t *output) {
    if (!key || !input || !output || input_len % 8 != 0) return false;

    if (key_len == 8) {
        mbedtls_des_context ctx;
        mbedtls_des_init(&ctx);
        mbedtls_des_setkey_dec(&ctx, key);
        for (size_t i = 0; i < input_len; i += 8) {
            mbedtls_des_crypt_ecb(&ctx, &input[i], &output[i]);
        }
        mbedtls_des_free(&ctx);
        return true;
    } else if (key_len == 16) {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        mbedtls_des3_set2key_dec(&ctx, key);
        for (size_t i = 0; i < input_len; i += 8) {
            mbedtls_des3_crypt_ecb(&ctx, &input[i], &output[i]);
        }
        mbedtls_des3_free(&ctx);
        return true;
    }
    return false;
}

bool fmcos_generate_mac(const uint8_t *key, size_t key_len, const uint8_t *iv, const uint8_t *input, size_t input_len, uint8_t *mac) {
    if (!key || !input || !mac) return false;
    if (key_len != 8 && key_len != 16) return false;

    uint8_t padded[256];
    size_t padded_len = 0;
    
    // Fall back to safe length max
    if (input_len > 240) return false;

    if (!fmcos_apply_padding(input, input_len, padded, sizeof(padded), &padded_len)) {
        return false;
    }

    uint8_t current_block[8];
    if (iv) {
        memcpy(current_block, iv, 8);
    } else {
        memset(current_block, 0, 8);
    }

    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    // PBOC MAC uses single DES for XOR chain regardless of Double length key
    mbedtls_des_setkey_enc(&ctx, key);

    for (size_t i = 0; i < padded_len; i += 8) {
        for (int j = 0; j < 8; j++) {
            current_block[j] ^= padded[i + j];
        }
        mbedtls_des_crypt_ecb(&ctx, current_block, current_block);
    }

    // For 3DES, the final block goes through DEA-1^-1 and DEA-1 again
    if (key_len == 16) {
        mbedtls_des_setkey_dec(&ctx, key + 8);
        mbedtls_des_crypt_ecb(&ctx, current_block, current_block);
        mbedtls_des_setkey_enc(&ctx, key);
        mbedtls_des_crypt_ecb(&ctx, current_block, current_block);
    }

    mbedtls_des_free(&ctx);

    // MAC is the left-most 4 bytes
    memcpy(mac, current_block, 4);
    return true;
}

bool fmcos_derive_process_key(const uint8_t *master_key, size_t key_len,
                              const uint8_t *random,
                              uint8_t *process_key) {
    if (!master_key || !random || !process_key) return false;
    if (key_len != 8 && key_len != 16) return false;

    // Build two 8-byte blocks from the 8-byte random:
    //   block_left  = random[0..3] || 00 00 00 00
    //   block_right = random[4..7] || 00 00 00 00
    uint8_t block_left[8] = {0};
    uint8_t block_right[8] = {0};
    memcpy(block_left, random, 4);
    memcpy(block_right, random + 4, 4);

    // Encrypt each block to produce the 16-byte process key
    // process_key[0..7]  = DES/3DES_ECB(master_key, block_left)
    // process_key[8..15] = DES/3DES_ECB(master_key, block_right)
    if (!fmcos_encrypt(master_key, key_len, block_left, 8, process_key)) {
        return false;
    }
    if (!fmcos_encrypt(master_key, key_len, block_right, 8, process_key + 8)) {
        return false;
    }

    return true;
}
