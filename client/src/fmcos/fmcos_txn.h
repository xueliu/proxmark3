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
// FMCOS Transaction Context Definitions
//-----------------------------------------------------------------------------

#ifndef _FMCOS_TXN_H_
#define _FMCOS_TXN_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    FMCOS_TXN_NONE = 0,
    FMCOS_TXN_LOAD,
    FMCOS_TXN_PURCHASE,
    FMCOS_TXN_CAPP_PURCHASE,
    FMCOS_TXN_UNLOAD,
    FMCOS_TXN_CASH_WITHDRAW,
    FMCOS_TXN_UPDATE_OD_LIMIT,
    FMCOS_TXN_GREY_LOCK,
    FMCOS_TXN_DEBIT_FOR_UNLOCK,
    FMCOS_TXN_GREY_UNLOCK
} fmcos_txn_type_t;

typedef enum {
    FMCOS_TXN_STATE_IDLE = 0,
    FMCOS_TXN_STATE_INITIALIZED,
    FMCOS_TXN_STATE_MAC_VERIFIED,
    FMCOS_TXN_STATE_COMMITTED,
    FMCOS_TXN_STATE_FAILED
} fmcos_txn_state_t;

// Standard transaction types (app_type)
#define FMCOS_TXNTYPE_LOAD_EP              0x01
#define FMCOS_TXNTYPE_LOAD_WALLET          0x02
#define FMCOS_TXNTYPE_UNLOAD               0x03
#define FMCOS_TXNTYPE_CASH_WITHDRAW        0x04
#define FMCOS_TXNTYPE_PURCHASE             0x06
#define FMCOS_TXNTYPE_CAPP_PURCHASE        0x09

typedef struct {
    fmcos_txn_state_t state;
    fmcos_txn_type_t type;
    uint8_t app_type;
    uint8_t key_id;
    uint8_t key_ver;
    uint8_t alg_id;
    uint8_t random[4];
    uint8_t term_id[6];
    uint8_t amount[4];
    uint8_t balance[4];
    uint8_t extra[16];
    uint8_t process_key[16];
    size_t process_key_len;
    uint8_t seq_online[2];
    uint8_t seq_offline[2];
    uint8_t od_limit[3];
} fmcos_txn_ctx_t;

// Forward declaration for fmcos_session_t pointer
struct fmcos_session;

/**
 * @brief Initialize a Load transaction
 */
int fmcos_txn_init_load(struct fmcos_session *session, uint8_t key_id, uint8_t pt, const uint8_t *amount, const uint8_t *term_id, const uint8_t *master_key, size_t master_key_len);

/**
 * @brief Commit a Load transaction
 */
int fmcos_txn_credit(struct fmcos_session *session, const uint8_t *host_date, const uint8_t *host_time);

/**
 * @brief Initialize a Purchase transaction
 */
int fmcos_txn_init_purchase(struct fmcos_session *session, uint8_t key_id, uint8_t pt, const uint8_t *amount, const uint8_t *term_id, const uint8_t *master_key, size_t master_key_len);

/**
 * @brief Commit a Purchase transaction
 */
int fmcos_txn_debit(struct fmcos_session *session, const uint8_t *term_date, const uint8_t *term_time);


#endif // _FMCOS_TXN_H_
