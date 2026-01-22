#ifndef _FMCOS_H_
#define _FMCOS_H_

#include <stdint.h>
#include <stdbool.h>
#include "proxmark3.h"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// CLA
#define FMCOS_CLA_ISO       0x00
#define FMCOS_CLA_MAC       0x04
#define FMCOS_CLA_PBOC      0x80
#define FMCOS_CLA_PBOC_MAC  0x84

// INS
#define FMCOS_INS_VERIFY        0x20
#define FMCOS_INS_EXT_AUTH      0x82
#define FMCOS_INS_GET_CHALLENGE 0x84
#define FMCOS_INS_INT_AUTH      0x88
#define FMCOS_INS_SELECT        0xA4
#define FMCOS_INS_READ_BINARY   0xB0
#define FMCOS_INS_READ_RECORD   0xB2
#define FMCOS_INS_GET_RESPONSE  0xC0
#define FMCOS_INS_UPDATE_BINARY 0xD6
#define FMCOS_INS_UPDATE_RECORD 0xDC
#define FMCOS_INS_APPEND_RECORD 0xE2

// Proprietary INS
#define FMCOS_INS_ERASE_DF      0x0E
#define FMCOS_INS_WRITE_KEY     0xD4
#define FMCOS_INS_CREATE_FILE   0xE0
#define FMCOS_INS_GET_BALANCE   0x5C
#define FMCOS_INS_INIT_LOAD     0x50
#define FMCOS_INS_CREDIT        0x52
#define FMCOS_INS_DEBIT         0x54
#define FMCOS_INS_CHANGE_PIN    0x5E
#define FMCOS_INS_PIN_UNBLOCK   0x24
#define FMCOS_INS_APP_BLOCK     0x1E
#define FMCOS_INS_APP_UNBLOCK   0x18

// Key Types
#define FMCOS_KEY_MASTER        0x30
#define FMCOS_KEY_MAINTAIN      0x33
#define FMCOS_KEY_APP_MASTER    0x31
#define FMCOS_KEY_APP_MAINTAIN  0x34
#define FMCOS_KEY_DES           0x35
#define FMCOS_KEY_PIN           0x3A
#define FMCOS_KEY_EXT_AUTH      0x39

// File Types
#define FMCOS_FILE_DF           0x38
#define FMCOS_FILE_BINARY       0x28
#define FMCOS_FILE_FIXED_REC    0x2A
#define FMCOS_FILE_VAR_REC      0x2C
#define FMCOS_FILE_CYCLIC_REC   0x2E
#define FMCOS_FILE_KEY          0x3F
#define FMCOS_FILE_WALLET       0x2F

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t sw1;
    uint8_t sw2;
    uint8_t *data;
    uint16_t len;
} fmcos_resp_t;

// ---------------------------------------------------------------------------
// Prototypes
// ---------------------------------------------------------------------------

// Core
int fmcos_info(void);
int fmcos_send_apdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                    const uint8_t *data, uint16_t len, uint8_t le,
                    uint8_t *resp, uint16_t *resplen, uint8_t *sw1, uint8_t *sw2);

// File Operations
int fmcos_select_file(uint16_t fid, uint8_t *resp, uint16_t *resplen, uint8_t *sw1, uint8_t *sw2);
int fmcos_select_path(const uint8_t *path, uint8_t len, uint8_t *sw1, uint8_t *sw2);
int fmcos_select_df(const uint8_t *aid, uint8_t len, uint8_t *sw1, uint8_t *sw2);
int fmcos_read_binary(uint16_t offset, uint8_t len, uint8_t sfi, uint8_t *out_data, uint8_t *sw1, uint8_t *sw2);
int fmcos_update_binary(uint16_t offset, const uint8_t *data, uint8_t len, uint8_t sfi, uint8_t *sw1, uint8_t *sw2);

// Create functions
int fmcos_create_df(uint16_t fid, uint8_t space, const uint8_t *df_name, uint8_t name_len, const uint8_t *perm, uint8_t *sw1, uint8_t *sw2);
int fmcos_create_key_file(uint8_t slots, const uint8_t *prop, uint8_t *sw1, uint8_t *sw2);
int fmcos_create_binary_ef(uint16_t fid, uint16_t size, const uint8_t *perm, uint8_t *sw1, uint8_t *sw2);
int fmcos_create_record_ef(uint16_t fid, uint8_t rec_type, uint8_t sfi, uint8_t count, uint8_t len, const uint8_t *perm, uint8_t *sw1, uint8_t *sw2);

// Security
int fmcos_get_challenge(uint8_t len, uint8_t *challenge);
int fmcos_ext_auth(uint8_t kid, const uint8_t *key_bytes, uint8_t key_len);
int fmcos_verify_pin(uint8_t kid, const uint8_t *pin, uint8_t len);

// Helpers
const char* fmcos_get_sw_desc(uint8_t sw1, uint8_t sw2);
void fmcos_set_verbose(bool verbose);
void fmcos_drop_field(void);

#endif
