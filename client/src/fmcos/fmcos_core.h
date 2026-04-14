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
// FMCOS Core Session and Exchange
//-----------------------------------------------------------------------------

#ifndef _FMCOS_CORE_H_
#define _FMCOS_CORE_H_

#include "fmcos_apdu.h"
#include "fmcos_sm.h"
#include "fmcos_txn.h"

// FMCOS Context / Session
typedef struct fmcos_session {
    bool connected;
    bool iso4_active;
    uint8_t uid[10];
    size_t uid_len;
    uint8_t ats[32];
    size_t ats_len;
    uint8_t cid;
    uint16_t fsc;
    uint32_t fwt_us;
    
    // Command Settings
    bool verbose;

    // Sub-Contexts
    fmcos_sm_ctx_t sm;
    fmcos_txn_ctx_t txn;
} fmcos_session_t;

/**
 * @brief Initialize a session to default state
 */
void fmcos_session_init(fmcos_session_t *session);

/**
 * @brief Exchange an APDU with the PICC.
 * 
 * Takes a structured APDU Request, serializes it, sends it via underlying transport (ExchangeAPDU14a),
 * and parses the response into the structured Response format. 
 * Also handles Secure Messaging wrapping if configured in the session.
 * 
 * @param session   Current FMCOS session
 * @param req       The Request APDU
 * @param resp      The Response APDU
 * @return PM3_SUCCESS on success, error code otherwise.
 */
int fmcos_exchange_apdu(fmcos_session_t *session, const fmcos_apdu_t *req, fmcos_resp_t *resp);

/**
 * @brief Manually drop the RF field and mark the session as disconnected.
 */
void fmcos_session_drop_field(fmcos_session_t *session);

#endif // _FMCOS_CORE_H_
