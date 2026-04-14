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
// FMCOS APDU Builder and Parser Implementation
//-----------------------------------------------------------------------------

#include "fmcos_apdu.h"
#include <string.h>

void fmcos_apdu_build_case1(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
    memset(apdu, 0, sizeof(fmcos_apdu_t));
    apdu->cla = cla;
    apdu->ins = ins;
    apdu->p1 = p1;
    apdu->p2 = p2;
    // defaults are has_lc=false, has_le=false
}

void fmcos_apdu_build_case2(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t le) {
    memset(apdu, 0, sizeof(fmcos_apdu_t));
    apdu->cla = cla;
    apdu->ins = ins;
    apdu->p1 = p1;
    apdu->p2 = p2;
    apdu->has_le = true;
    apdu->le = le;
}

void fmcos_apdu_build_case3(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, uint16_t lc) {
    memset(apdu, 0, sizeof(fmcos_apdu_t));
    apdu->cla = cla;
    apdu->ins = ins;
    apdu->p1 = p1;
    apdu->p2 = p2;
    if (lc > 0 && data != NULL) {
        apdu->has_lc = true;
        apdu->lc = lc;
        uint16_t copy_len = (lc > 255) ? 255 : lc;
        memcpy(apdu->data, data, copy_len);
    }
}

void fmcos_apdu_build_case4(fmcos_apdu_t *apdu, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, uint16_t lc, uint8_t le) {
    memset(apdu, 0, sizeof(fmcos_apdu_t));
    apdu->cla = cla;
    apdu->ins = ins;
    apdu->p1 = p1;
    apdu->p2 = p2;
    if (lc > 0 && data != NULL) {
        apdu->has_lc = true;
        apdu->lc = lc;
        uint16_t copy_len = (lc > 255) ? 255 : lc;
        memcpy(apdu->data, data, copy_len);
    }
    apdu->has_le = true;
    apdu->le = le;
}

bool fmcos_apdu_serialize(const fmcos_apdu_t *apdu, uint8_t *buffer, uint16_t *out_len) {
    if (!apdu || !buffer || !out_len) return false;

    uint16_t len = 0;
    buffer[len++] = apdu->cla;
    buffer[len++] = apdu->ins;
    buffer[len++] = apdu->p1;
    buffer[len++] = apdu->p2;

    if (apdu->has_lc) {
        buffer[len++] = (uint8_t)(apdu->lc & 0xFF);
        memcpy(&buffer[len], apdu->data, apdu->lc);
        len += apdu->lc;
    }

    if (apdu->has_le) {
        buffer[len++] = (uint8_t)(apdu->le & 0xFF);
    }

    *out_len = len;
    return true;
}

bool fmcos_resp_parse(const uint8_t *buffer, size_t len, fmcos_resp_t *resp) {
    if (!buffer || !resp) return false;
    if (len < 2) return false;

    memset(resp, 0, sizeof(fmcos_resp_t));
    
    resp->sw1 = buffer[len - 2];
    resp->sw2 = buffer[len - 1];
    
    if (len > 2) {
        resp->data_len = len - 2;
        size_t copy_len = (resp->data_len > sizeof(resp->data)) ? sizeof(resp->data) : resp->data_len;
        memcpy(resp->data, buffer, copy_len);
    }
    return true;
}
