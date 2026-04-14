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
// FMCOS Transaction Stub Implementation
//-----------------------------------------------------------------------------

#include "fmcos_txn.h"
#include "fmcos_core.h"
#include "fmcos_status.h"
#include "fmcos_crypto.h"
#include "fmcos.h"
#include "ui.h"
#include <string.h>

/**
 * @brief Initialize a LOAD transaction (EP/Wallet).
 */
int fmcos_txn_init_load(struct fmcos_session *session, uint8_t key_id, uint8_t pt, const uint8_t *amount, const uint8_t *term_id, const uint8_t *master_key, size_t master_key_len) {
    if (!session || !amount || !term_id || !master_key) return PM3_EINVARG;

    fmcos_apdu_t req;
    uint8_t data[11];
    data[0] = key_id;
    memcpy(data + 1, amount, 4);
    memcpy(data + 5, term_id, 6);

    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_INIT_LOAD, 0x00, pt, data, 11);
    req.has_le = true;
    req.le = 0x10; // expected len 16
    
    fmcos_resp_t resp;
    int ret = fmcos_exchange_apdu(session, &req, &resp);
    if (ret != PM3_SUCCESS || !fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return ret != PM3_SUCCESS ? ret : PM3_EIO;
    }

    if (resp.data_len < 16) {
        PrintAndLogEx(ERR, "INIT LOAD: response too short (%zu)", resp.data_len);
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return PM3_EIO;
    }

    // Parse response
    // old_balance[4], seq[2], key_ver[1], alg_id[1], random[4], MAC1[4]
    memcpy(session->txn.balance, resp.data, 4);
    memcpy(session->txn.seq_online, resp.data + 4, 2);
    session->txn.key_ver = resp.data[6];
    session->txn.alg_id = resp.data[7];
    memcpy(session->txn.random, resp.data + 8, 4);
    uint8_t card_mac1[4];
    memcpy(card_mac1, resp.data + 12, 4);

    // Save inputs
    session->txn.type = FMCOS_TXN_LOAD;
    session->txn.app_type = (pt == 0x01) ? FMCOS_TXNTYPE_LOAD_EP : FMCOS_TXNTYPE_LOAD_WALLET;
    session->txn.key_id = key_id;
    memcpy(session->txn.amount, amount, 4);
    memcpy(session->txn.term_id, term_id, 6);

    // Derive process key: random[4] || online_seq[2] || 80 00
    uint8_t pr_input[8];
    memcpy(pr_input, session->txn.random, 4);
    memcpy(pr_input + 4, session->txn.seq_online, 2);
    pr_input[6] = 0x80;
    pr_input[7] = 0x00;

    if (!fmcos_derive_process_key(master_key, master_key_len, pr_input, session->txn.process_key)) {
        PrintAndLogEx(ERR, "INIT LOAD: Failed to derive process key");
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return PM3_EIO;
    }
    session->txn.process_key_len = 16;

    // Verify MAC1
    // Input: old_balance[4] || amount[4] || txn_type[1] || term_id[6]
    uint8_t mac1_input[15];
    memcpy(mac1_input, session->txn.balance, 4);
    memcpy(mac1_input + 4, session->txn.amount, 4);
    mac1_input[8] = session->txn.app_type;
    memcpy(mac1_input + 9, session->txn.term_id, 6);

    uint8_t computed_mac1[4];
    if (!fmcos_generate_mac(session->txn.process_key, session->txn.process_key_len, NULL, mac1_input, 15, computed_mac1)) {
        PrintAndLogEx(ERR, "INIT LOAD: Failed to compute MAC1");
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return PM3_EIO;
    }

    if (memcmp(computed_mac1, card_mac1, 4) != 0) {
        PrintAndLogEx(ERR, "INIT LOAD: MAC1 mismatch! Expected: %02X%02X%02X%02X, Got: %02X%02X%02X%02X",
                      computed_mac1[0], computed_mac1[1], computed_mac1[2], computed_mac1[3],
                      card_mac1[0], card_mac1[1], card_mac1[2], card_mac1[3]);
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return PM3_EIO;
    }

    session->txn.state = FMCOS_TXN_STATE_MAC_VERIFIED;
    return PM3_SUCCESS;
}

/**
 * @brief Commit a LOAD transaction (CREDIT FOR LOAD).
 */
int fmcos_txn_credit(struct fmcos_session *session, const uint8_t *host_date, const uint8_t *host_time) {
    if (!session || !host_date || !host_time) return PM3_EINVARG;
    if (session->txn.state != FMCOS_TXN_STATE_MAC_VERIFIED || session->txn.type != FMCOS_TXN_LOAD) {
        PrintAndLogEx(ERR, "TXN: Invalid state or type for CREDIT");
        return PM3_EIO;
    }

    // Compute MAC2
    // Input: amount[4] || txn_type[1] || term_id[6] || host_date[4] || host_time[3]
    uint8_t mac2_input[18];
    memcpy(mac2_input, session->txn.amount, 4);
    mac2_input[4] = session->txn.app_type;
    memcpy(mac2_input + 5, session->txn.term_id, 6);
    memcpy(mac2_input + 11, host_date, 4);
    memcpy(mac2_input + 15, host_time, 3);

    uint8_t mac2[4];
    if (!fmcos_generate_mac(session->txn.process_key, session->txn.process_key_len, NULL, mac2_input, 18, mac2)) {
        PrintAndLogEx(ERR, "CREDIT: Failed to compute MAC2");
        return PM3_EIO;
    }

    // Build APDU: 80 52 00 00 0B host_date[4] host_time[3] MAC2[4]
    fmcos_apdu_t req;
    uint8_t data[11];
    memcpy(data, host_date, 4);
    memcpy(data + 4, host_time, 3);
    memcpy(data + 7, mac2, 4);

    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_CREDIT, 0x00, 0x00, data, 11);
    req.has_le = true;
    req.le = 0x04; // TAC expected

    fmcos_resp_t resp;
    int ret = fmcos_exchange_apdu(session, &req, &resp);
    
    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        session->txn.state = FMCOS_TXN_STATE_COMMITTED;
        if (session->verbose && resp.data_len >= 4) {
             PrintAndLogEx(INFO, "TAC: %02X%02X%02X%02X", resp.data[0], resp.data[1], resp.data[2], resp.data[3]);
             // Note: TAC verification usually done if card and logic implement full DTK left-right logic.
        }
    } else {
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return ret != PM3_SUCCESS ? ret : PM3_EIO;
    }

    return PM3_SUCCESS;
}

/**
 * @brief Initialize a PURCHASE transaction (EP/Wallet).
 */
int fmcos_txn_init_purchase(struct fmcos_session *session, uint8_t key_id, uint8_t pt, const uint8_t *amount, const uint8_t *term_id, const uint8_t *master_key, size_t master_key_len) {
    if (!session || !amount || !term_id || !master_key) return PM3_EINVARG;

    fmcos_apdu_t req;
    uint8_t data[11];
    data[0] = key_id;
    memcpy(data + 1, amount, 4);
    memcpy(data + 5, term_id, 6);

    // Initializing PURCHASE: INS is still 50, but parameters differ
    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_INIT_LOAD, 0x01, pt, data, 11);
    req.has_le = true;
    req.le = 0x0F; // expected len 15
    
    fmcos_resp_t resp;
    int ret = fmcos_exchange_apdu(session, &req, &resp);
    if (ret != PM3_SUCCESS || !fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return ret != PM3_SUCCESS ? ret : PM3_EIO;
    }

    if (resp.data_len < 15) {
        PrintAndLogEx(ERR, "INIT PURCHASE: response too short (%zu)", resp.data_len);
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return PM3_EIO;
    }

    // Parse response
    // old_balance[4], offline_seq[2], overdraw_limit[3], key_ver[1], alg_id[1], random[4]
    memcpy(session->txn.balance, resp.data, 4);
    memcpy(session->txn.seq_offline, resp.data + 4, 2);
    memcpy(session->txn.od_limit, resp.data + 6, 3);
    session->txn.key_ver = resp.data[9];
    session->txn.alg_id = resp.data[10];
    memcpy(session->txn.random, resp.data + 11, 4);

    // Save inputs
    session->txn.type = FMCOS_TXN_PURCHASE;
    session->txn.app_type = FMCOS_TXNTYPE_PURCHASE; 
    session->txn.key_id = key_id;
    memcpy(session->txn.amount, amount, 4);
    memcpy(session->txn.term_id, term_id, 6);

    session->txn.state = FMCOS_TXN_STATE_INITIALIZED;
    return PM3_SUCCESS;
}

/**
 * @brief Commit a PURCHASE transaction (DEBIT FOR PURCHASE).
 */
int fmcos_txn_debit(struct fmcos_session *session, const uint8_t *term_date, const uint8_t *term_time) {
    if (!session || !term_date || !term_time) return PM3_EINVARG;
    if (session->txn.state != FMCOS_TXN_STATE_INITIALIZED || session->txn.type != FMCOS_TXN_PURCHASE) {
        PrintAndLogEx(ERR, "TXN: Invalid state or type for PURCHASE DEBIT");
        return PM3_EIO;
    }

    // Note: To compute MAC1 for DEBIT, we need the derived process key, but during purchase
    // it usually uses the offline_seq and terminal transaction sequences. 
    // This requires specific implementation matching the PBOC manual.
    // For now, we are providing the skeleton and basic parameters assuming it will be expanded
    // if a full purchase simulator is built.
    
    // 80 54 01 00 0F term_txn_seq[4] date[4] time[3] MAC1[4]
    PrintAndLogEx(WARNING, "DEBIT FOR PURCHASE MAC computation not fully implemented, sending zeros MAC.");
    
    fmcos_apdu_t req;
    uint8_t data[15] = {0};
    uint8_t dummy_seq[4] = {0,0,0,1};
    memcpy(data, dummy_seq, 4);
    memcpy(data + 4, term_date, 4);
    memcpy(data + 8, term_time, 3);
    // data[11..14] is zero MAC

    fmcos_apdu_build_case3(&req, FMCOS_CLA_PBOC, FMCOS_INS_DEBIT, 0x01, 0x00, data, 15);
    req.has_le = true;
    req.le = 0x08; // TAC + MAC2 expected

    fmcos_resp_t resp;
    int ret = fmcos_exchange_apdu(session, &req, &resp);
    
    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        session->txn.state = FMCOS_TXN_STATE_COMMITTED;
    } else {
        session->txn.state = FMCOS_TXN_STATE_FAILED;
        return ret != PM3_SUCCESS ? ret : PM3_EIO;
    }

    return PM3_SUCCESS;
}
