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
// FMCOS Cryptography (DES/3DES/MAC)
//-----------------------------------------------------------------------------

#ifndef _FMCOS_CRYPTO_H_
#define _FMCOS_CRYPTO_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Apply PBOC 80 00... padding to input buffer.
 * 
 * @param in           Input data buffer
 * @param in_len       Input data length
 * @param out          Output padded buffer (must be large enough)
 * @param out_max_len  Maximum capacity of out buffer
 * @param out_len      Resulting length (will be a multiple of 8)
 * @return true on success
 */
bool fmcos_apply_padding(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max_len, size_t *out_len);

/**
 * @brief Encrypt a block or multiple blocks with DES or 3DES (ECB mode).
 * 
 * @param key       DES key (8 bytes) or 3DES key (16 bytes)
 * @param key_len   8 or 16
 * @param input     Data to encrypt (multiple of 8 bytes)
 * @param input_len Length of input
 * @param output    Encrypted data
 * @return true on success
 */
bool fmcos_encrypt(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len, uint8_t *output);

/**
 * @brief Decrypt a block or multiple blocks with DES or 3DES (ECB mode).
 * 
 * @param key       DES key (8 bytes) or 3DES key (16 bytes)
 * @param key_len   8 or 16
 * @param input     Data to decrypt (multiple of 8 bytes)
 * @param input_len Length of input
 * @param output    Decrypted data
 * @return true on success
 */
bool fmcos_decrypt(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len, uint8_t *output);

/**
 * @brief Generate PBOC MAC.
 * 
 * Typically uses single DES encryption, XORing previous blocks.
 * 
 * @param key       MAC Key (typically 8 bytes)
 * @param key_len   Length of MAC Key
 * @param iv        Initial Vector (8 bytes, usually 0x00...)
 * @param input     Data to MAC (will be padded internally)
 * @param input_len Data length
 * @param mac       Output 4-byte MAC
 * @return true on success
 */
bool fmcos_generate_mac(const uint8_t *key, size_t key_len, const uint8_t *iv, const uint8_t *input, size_t input_len, uint8_t *mac);

/**
 * @brief Derive PBOC process key from master key and random.
 *
 * Process key = 3DES_ECB(master_key, random[0..3] || 0x00...) ||
 *               3DES_ECB(master_key, random[4..7] || 0x00...)
 * (For 8-byte random, split into two 4-byte halves, each padded to 8 and encrypted)
 *
 * @param master_key  The master/diversification key (8 or 16 bytes)
 * @param key_len     Master key length
 * @param random      8-byte random from card (from INIT FOR LOAD/PURCHASE response)
 * @param process_key Output 16-byte derived process key
 * @return true on success
 */
bool fmcos_derive_process_key(const uint8_t *master_key, size_t key_len,
                              const uint8_t *random,
                              uint8_t *process_key);

#endif // _FMCOS_CRYPTO_H_
