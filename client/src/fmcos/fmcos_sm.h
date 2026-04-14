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
// FMCOS Secure Messaging (SM) - Command MAC / Encrypt+MAC wrapping
//
// FMCOS 2.0 SM Protocol:
//   MAC-only (CLA |= 0x04):
//     Command:  CLA INS P1 P2 Lc [Data] MAC(4)
//       MAC input = CLA INS P1 P2 Lc [Data], padded to 8-byte boundary
//       MAC key = line-protection key (session key after ext auth)
//     Response: [Data] MAC(4) SW1 SW2
//       Verify MAC over response data
//
//   ENC+MAC (CLA |= 0x04):
//     Command:  CLA INS P1 P2 Lc ENC(Data) MAC(4)
//       Data is padded (80 00...) then 3DES-ECB encrypted
//       MAC computed over CLA INS P1 P2 Lc ENC(Data)
//     Response: ENC([Data]) MAC(4) SW1 SW2
//       Decrypt then verify MAC
//-----------------------------------------------------------------------------

#ifndef _FMCOS_SM_H_
#define _FMCOS_SM_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "fmcos_apdu.h"

typedef enum {
    FMCOS_SM_NONE = 0,
    FMCOS_SM_MAC_ONLY,
    FMCOS_SM_ENC_MAC
} fmcos_sm_mode_t;

typedef struct {
    fmcos_sm_mode_t mode;
    uint8_t mac_key[16];     // MAC key (left 8 bytes used for PBOC MAC chain)
    size_t mac_key_len;      // 8 = DES, 16 = 3DES
    uint8_t enc_key[16];     // Encryption key (for ENC+MAC mode)
    size_t enc_key_len;
    uint8_t key_id;          // Key ID used for authentication
    uint8_t iv[8];           // IV for MAC chain (usually zeroes)
} fmcos_sm_ctx_t;

/**
 * @brief Activate SM context with a key for MAC-only mode.
 */
void fmcos_sm_activate_mac(fmcos_sm_ctx_t *ctx, uint8_t key_id,
                           const uint8_t *mac_key, size_t mac_key_len);

/**
 * @brief Activate SM context with keys for ENC+MAC mode.
 */
void fmcos_sm_activate_enc_mac(fmcos_sm_ctx_t *ctx, uint8_t key_id,
                               const uint8_t *enc_key, size_t enc_key_len,
                               const uint8_t *mac_key, size_t mac_key_len);

/**
 * @brief Deactivate SM (set mode to NONE).
 */
void fmcos_sm_deactivate(fmcos_sm_ctx_t *ctx);

/**
 * @brief Wrap an outgoing APDU with SM protection.
 *
 * For MAC_ONLY:
 *   - Sets CLA |= 0x04
 *   - Computes PBOC MAC over (CLA INS P1 P2 Lc [Data])
 *   - Appends 4-byte MAC to data, adjusts Lc
 *
 * For ENC_MAC:
 *   - Sets CLA |= 0x04
 *   - Pads Data with 80 00..., encrypts with enc_key
 *   - Computes MAC over (CLA INS P1 P2 Lc ENC(Data))
 *   - Appends 4-byte MAC, adjusts Lc
 *
 * @param ctx       SM context
 * @param apdu      APDU to wrap (modified in place)
 * @return true on success
 */
bool fmcos_sm_wrap_command(const fmcos_sm_ctx_t *ctx, fmcos_apdu_t *apdu);

/**
 * @brief Verify (and optionally decrypt) an incoming SM response.
 *
 * For MAC_ONLY:
 *   - Last 4 bytes of resp->data are the MAC
 *   - Verify MAC over preceding data bytes
 *   - Trim MAC from data_len
 *
 * For ENC_MAC:
 *   - Split data into ENC(payload) + MAC(4)
 *   - Verify MAC over ENC(payload)
 *   - Decrypt ENC(payload), remove padding
 *   - Update resp->data and data_len
 *
 * @param ctx       SM context
 * @param resp      Response to verify/unwrap (modified in place)
 * @return true if MAC verified OK
 */
bool fmcos_sm_unwrap_response(const fmcos_sm_ctx_t *ctx, fmcos_resp_t *resp);

#endif // _FMCOS_SM_H_
