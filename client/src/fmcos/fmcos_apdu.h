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
// FMCOS APDU Builder and Parser
//-----------------------------------------------------------------------------

#ifndef _FMCOS_APDU_H_
#define _FMCOS_APDU_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Standard APDU structure for FMCOS (ISO 7816-4)
typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint16_t lc;           // Max 255 for standard APDU
    uint8_t data[256];     // Payload
    bool has_lc;
    bool has_le;
    uint16_t le;           // Max 256
} fmcos_apdu_t;

// Standard Response structure
typedef struct {
    uint8_t data[256];
    size_t data_len;
    uint8_t sw1;
    uint8_t sw2;
} fmcos_resp_t;

/**
 * @brief Initialize a Case 1 APDU (No Data in, No Data out)
 */
void fmcos_apdu_build_case1(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);

/**
 * @brief Initialize a Case 2 APDU (No Data in, Data out)
 */
void fmcos_apdu_build_case2(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t le);

/**
 * @brief Initialize a Case 3 APDU (Data in, No Data out)
 */
void fmcos_apdu_build_case3(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, uint16_t lc);

/**
 * @brief Initialize a Case 4 APDU (Data in, Data out)
 */
void fmcos_apdu_build_case4(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, uint16_t lc, uint8_t le);

/**
 * @brief Serialize the apdu structure into a byte array
 * 
 * @param apdu The structural APDU
 * @param buffer Output buffer (min 261 bytes recommended)
 * @param out_len resulting length of the byte stream
 * @return true on success, false if invalid
 */
bool fmcos_apdu_serialize(const fmcos_apdu_t *apdu, uint8_t *buffer, uint16_t *out_len);

/**
 * @brief Parse a raw byte stream from the PICC into a structured response
 * 
 * @param buffer Raw PICC rx buffer
 * @param len Total length of the response
 * @param resp The structured response output
 * @return true on success, false if parsing failed (e.g. len < 2)
 */
bool fmcos_resp_parse(const uint8_t *buffer, size_t len, fmcos_resp_t *resp);

#endif // _FMCOS_APDU_H_
