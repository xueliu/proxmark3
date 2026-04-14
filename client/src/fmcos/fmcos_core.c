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
// FMCOS Core Session and Exchange Implementation
//-----------------------------------------------------------------------------

#include "fmcos_core.h"
#include "fmcos_status.h"
#include "fmcos_sm.h"
#include "cmdhf14a.h"  // For ExchangeAPDU14a and DropField
#include "ui.h"
#include <string.h>
#include <stdio.h>

void fmcos_session_init(fmcos_session_t *session) {
    if (!session) return;
    memset(session, 0, sizeof(fmcos_session_t));
    session->fsc = 32; // Default starting FSC
    session->verbose = false;
}

void fmcos_session_drop_field(fmcos_session_t *session) {
    DropField();
    if (session) {
        session->connected = false;
        session->iso4_active = false;
        // Deactivate SM on field drop
        fmcos_sm_deactivate(&session->sm);
    }
}

int fmcos_exchange_apdu(fmcos_session_t *session, const fmcos_apdu_t *req, fmcos_resp_t *resp) {
    if (!session || !req || !resp) return PM3_EINVARG;

    // 1. Copy request so we can modify it for SM
    fmcos_apdu_t final_req = *req;

    // 2. Secure Messaging Wrapping (if active)
    if (session->sm.mode != FMCOS_SM_NONE) {
        if (!fmcos_sm_wrap_command(&session->sm, &final_req)) {
            PrintAndLogEx(ERR, "SM wrapping failed");
            return PM3_EIO;
        }
        if (session->verbose) {
            PrintAndLogEx(INFO, "-- SM: wrapped command (CLA=%02X, Lc=%d)", final_req.cla, final_req.lc);
        }
    }

    // 3. Serialize APDU
    uint8_t apdu_buf[512];
    uint16_t apdu_len = 0;
    
    if (!fmcos_apdu_serialize(&final_req, apdu_buf, &apdu_len)) {
        PrintAndLogEx(ERR, "Failed to serialize APDU.");
        return PM3_EINVARG;
    }

    if (session->verbose) {
        char hex[1024] = {0};
        for(uint16_t i=0; i<apdu_len; i++) snprintf(hex+i*2, sizeof(hex)-i*2, "%02X", apdu_buf[i]);
        PrintAndLogEx(INFO, ">> APDU: %s", hex);
    }

    // 4. Transceive over ISO14443-4
    uint8_t raw_resp[512] = {0};
    int raw_resp_len = 0;
    
    bool activate = !session->connected;
    int ret = ExchangeAPDU14a(apdu_buf, apdu_len, activate, true, raw_resp, sizeof(raw_resp), &raw_resp_len);
    
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "ISO14443-4 Exchange failed (ret=%d)", ret);
        return PM3_EIO;
    }

    session->connected = true;
    session->iso4_active = true;

    // 5. Parse Response
    if (!fmcos_resp_parse(raw_resp, raw_resp_len, resp)) {
        PrintAndLogEx(ERR, "Failed to parse Response (len=%d)", raw_resp_len);
        return PM3_EIO;
    }

    if (session->verbose) {
        if (resp->data_len > 0) {
            char hex[1024] = {0};
            for(size_t i=0; i<resp->data_len; i++) snprintf(hex+i*2, sizeof(hex)-i*2, "%02X", resp->data[i]);
            PrintAndLogEx(INFO, "<< Data: %s", hex);
        }
        PrintAndLogEx(INFO, "<< SW: %02X%02X (%s)", resp->sw1, resp->sw2, fmcos_status_to_string(resp->sw1, resp->sw2));
    }

    // 6. Secure Messaging Unwrapping (if active and response is success)
    if (session->sm.mode != FMCOS_SM_NONE && fmcos_status_is_ok(resp->sw1, resp->sw2)) {
        if (resp->data_len >= 4) {
            if (!fmcos_sm_unwrap_response(&session->sm, resp)) {
                PrintAndLogEx(WARNING, "SM: response MAC verification failed");
                // Don't return error - let caller decide based on SW
            } else if (session->verbose) {
                PrintAndLogEx(INFO, "-- SM: response MAC verified OK");
            }
        }
    }

    return PM3_SUCCESS;
}

