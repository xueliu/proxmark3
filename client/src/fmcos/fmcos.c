#include "fmcos.h"
#include "cmdtrace.h"
#include "comms.h"
#include "pm3_binlib.h"
#include "pm3_cmd.h"
#include "ui.h"
#include "cmdhf14a.h"  // ExchangeAPDU14a
#include <string.h>
#include <stdio.h>

// Helper
const char* fmcos_get_sw_desc(uint8_t sw1, uint8_t sw2) {
    uint16_t sw = (sw1 << 8) | sw2;
    switch (sw) {
        case 0x9000: return "Success";
        case 0x6281: return "Part of data may be corrupted";
        case 0x6283: return "Selected file invalidated";
        case 0x6300: return "Verification failed";
        case 0x6581: return "Memory failure";
        case 0x6700: return "Wrong length";
        case 0x6882: return "Secure messaging not supported";
        case 0x6982: return "Security status not satisfied";
        case 0x6983: return "Auth blocked";
        case 0x6984: return "Ref data not usable";
        case 0x6985: return "Conditions not satisfied";
        case 0x6986: return "Command not allowed (no EF)";
        case 0x6A80: return "Incorrect data";
        case 0x6A81: return "Func not supported";
        case 0x6A82: return "File not found";
        case 0x6A83: return "Record not found";
        case 0x6A84: return "No memory";
        case 0x6A86: return "Incorrect P1-P2";
        case 0x6A88: return "Key not found";
        case 0x6B00: return "Wrong P1-P2";
        case 0x6D00: return "INS not supported";
        case 0x6E00: return "CLA not supported";
        case 0x6F00: return "Unknown error";
        case 0x9302: return "MAC error";
        case 0x9303: return "App locked";
        case 0x9401: return "Insufficient balance";
        case 0x9403: return "Key not found(2)";
        default: return "Unknown";
    }
}

static bool g_fmcos_verbose = false;
static bool g_fmcos_field_on = false;

void fmcos_set_verbose(bool verbose) {
    g_fmcos_verbose = verbose;
}

int fmcos_send_apdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                    const uint8_t *data, uint16_t len, uint8_t le,
                    uint8_t *resp, uint16_t *resplen, uint8_t *sw1, uint8_t *sw2) {
    
    uint8_t apdu[512];
    uint16_t apdu_len = 0;
    
    apdu[apdu_len++] = cla;
    apdu[apdu_len++] = ins;
    apdu[apdu_len++] = p1;
    apdu[apdu_len++] = p2;
    
    if (len > 0 && data != NULL) {
        apdu[apdu_len++] = (uint8_t)len;
        memcpy(&apdu[apdu_len], data, len);
        apdu_len += len;
    }
    
    if (le > 0) {
        apdu[apdu_len++] = le;
    }

    if (g_fmcos_verbose) {
        char hex[1024] = {0};
        for(int i=0; i<apdu_len; i++) sprintf(hex+i*2, "%02X", apdu[i]);
        PrintAndLogEx(INFO, ">> APDU: %s", hex);
    }

    // Use ExchangeAPDU14a - handles card activation and field management
    uint8_t response[512] = {0};
    int response_len = 0;
    
    // activateField = true for first command (when field not on)
    // leaveSignalON = true (keep field on for subsequent commands)
    bool activate = !g_fmcos_field_on;
    
    int ret = ExchangeAPDU14a(apdu, apdu_len, activate, true, response, sizeof(response), &response_len);
    
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "APDU exchange failed (ret=%d)", ret);
        return PM3_EIO;
    }
    
    g_fmcos_field_on = true;  // Field is now on
    
    if (response_len < 2) {
        PrintAndLogEx(ERR, "Response too short (less than 2 bytes SW)");
        return PM3_EIO;
    }

    // Extract SW (last 2 bytes of response)
    uint8_t r_sw1 = response[response_len - 2];
    uint8_t r_sw2 = response[response_len - 1];
    
    if (g_fmcos_verbose) {
        int data_len = response_len - 2;
        if (data_len > 0) {
            char hex[1024] = {0};
            for(int i=0; i<data_len; i++) sprintf(hex+i*2, "%02X", response[i]);
            PrintAndLogEx(INFO, "<< Data: %s", hex);
        }
        PrintAndLogEx(INFO, "<< SW: %02X%02X (%s)", r_sw1, r_sw2, fmcos_get_sw_desc(r_sw1, r_sw2));
    }

    if (sw1) *sw1 = r_sw1;
    if (sw2) *sw2 = r_sw2;
    
    // Copy data (excluding SW)
    if (response_len > 2) {
        if (resp && resplen) {
            uint16_t copy_len = response_len - 2;
            if (copy_len > *resplen) copy_len = *resplen;
            memcpy(resp, response, copy_len);
            *resplen = copy_len;
        }
    } else {
        if (resplen) *resplen = 0;
    }
    
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// File Operations
// ---------------------------------------------------------------------------

int fmcos_select_file(uint16_t fid, uint8_t *resp, uint16_t *resplen, uint8_t *sw1, uint8_t *sw2) {
    uint8_t data[2] = {fid >> 8, fid & 0xFF};
    return fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_SELECT, 0x00, 0x00, data, 2, 0x00, resp, resplen, sw1, sw2);
}

int fmcos_select_path(const uint8_t *path, uint8_t len, uint8_t *sw1, uint8_t *sw2) {
    if (len % 2 != 0) return PM3_ESOFT; // FID is 2 bytes
    uint8_t s1, s2;
    for (int i = 0; i < len; i += 2) {
        uint8_t data[2] = {path[i], path[i+1]};
        int ret = fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_SELECT, 0x00, 0x00, data, 2, 0x00, NULL, NULL, &s1, &s2);
        if (ret != PM3_SUCCESS) return ret;
        if (sw1) *sw1 = s1;
        if (sw2) *sw2 = s2;
        if (s1 != 0x90 || s2 != 0x00) return PM3_EIO; // Card error
    }
    return PM3_SUCCESS;
}

int fmcos_select_df(const uint8_t *aid, uint8_t len, uint8_t *sw1, uint8_t *sw2) {
    return fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_SELECT, 0x04, 0x00, aid, len, 0x00, NULL, NULL, sw1, sw2);
}

int fmcos_read_binary(uint16_t offset, uint8_t len, uint8_t sfi, uint8_t *out_data, uint8_t *sw1, uint8_t *sw2) {
    uint8_t p1, p2;
    if (sfi) {
        p1 = 0x80 | (sfi & 0x1F);
        p2 = offset & 0xFF;
    } else {
        p1 = (offset >> 8) & 0x7F;
        p2 = offset & 0xFF;
    }
    uint16_t rlen = len;
    return fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_READ_BINARY, p1, p2, NULL, 0, len, out_data, &rlen, sw1, sw2);
}

int fmcos_update_binary(uint16_t offset, const uint8_t *data, uint8_t len, uint8_t sfi, uint8_t *sw1, uint8_t *sw2) {
    uint8_t p1, p2;
    if (sfi) {
        p1 = 0x80 | (sfi & 0x1F);
        p2 = offset & 0xFF;
    } else {
        p1 = (offset >> 8) & 0x7F;
        p2 = offset & 0xFF;
    }
    return fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_UPDATE_BINARY, p1, p2, data, len, 0, NULL, NULL, sw1, sw2);
}

int fmcos_get_challenge(uint8_t len, uint8_t *challenge) {
    uint16_t rlen = len;
    uint8_t sw1, sw2;
    int ret = fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_GET_CHALLENGE, 0x00, 0x00, NULL, 0, len, challenge, &rlen, &sw1, &sw2);
    if (ret != PM3_SUCCESS) return ret;
    if (sw1 != 0x90 || sw2 != 0x00) return PM3_EIO;
    return PM3_SUCCESS;
}

#include "mbedtls/des.h"

int fmcos_ext_auth(uint8_t kid, const uint8_t *key_bytes, uint8_t key_len) {
    if (!key_bytes) return PM3_EINVARG;
    
    uint8_t rnd[8];
    uint8_t cryptogram[8];
    uint8_t sw1, sw2;
    int ret;

    ret = fmcos_get_challenge(8, rnd);
    if (ret != PM3_SUCCESS) return ret;

    if (key_len == 8) {
        // Single DES encryption
        mbedtls_des_context ctx;
        mbedtls_des_init(&ctx);
        mbedtls_des_setkey_enc(&ctx, key_bytes);
        mbedtls_des_crypt_ecb(&ctx, rnd, cryptogram);
        mbedtls_des_free(&ctx);
    } else if (key_len == 16) {
        // 3DES encryption (2-key)
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        mbedtls_des3_set2key_enc(&ctx, key_bytes);
        mbedtls_des3_crypt_ecb(&ctx, rnd, cryptogram);
        mbedtls_des3_free(&ctx);
    } else {
        return PM3_EINVARG;
    }

    // Send Auth
    return fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_EXT_AUTH, kid, 0x00, cryptogram, 8, 0, NULL, NULL, &sw1, &sw2);
}

int fmcos_verify_pin(uint8_t kid, const uint8_t *pin, uint8_t len) {
    uint8_t sw1, sw2;
    // CLA=00, INS=20, P1=00, P2=kid
    return fmcos_send_apdu(FMCOS_CLA_ISO, FMCOS_INS_VERIFY, 0x00, kid, pin, len, 0, NULL, NULL, &sw1, &sw2);
}

// Create DF (Directory File)
// Data: Type(0x38) + Space(1) + Reserved(00) + Perm(5) + DFName(n)
int fmcos_create_df(uint16_t fid, uint8_t space, const uint8_t *df_name, uint8_t name_len,
                    const uint8_t *perm, uint8_t *sw1, uint8_t *sw2) {
    uint8_t data[32];
    uint8_t data_len = 0;
    
    // Default permissions if not provided: F0 F0 95 FF FF
    const uint8_t default_perm[5] = {0xF0, 0xF0, 0x95, 0xFF, 0xFF};
    const uint8_t *use_perm = perm ? perm : default_perm;
    
    data[data_len++] = FMCOS_FILE_DF;  // 0x38
    data[data_len++] = space;
    data[data_len++] = 0x00;  // Reserved
    memcpy(data + data_len, use_perm, 5);
    data_len += 5;
    if (df_name && name_len > 0) {
        memcpy(data + data_len, df_name, name_len);
        data_len += name_len;
    }
    
    uint8_t p1 = (fid >> 8) & 0xFF;
    uint8_t p2 = fid & 0xFF;
    return fmcos_send_apdu(FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, p1, p2, data, data_len, 0, NULL, NULL, sw1, sw2);
}

// Create Key File
// Data: Type(0x3F) + Slots(1) + Prop(5)
int fmcos_create_key_file(uint8_t slots, const uint8_t *prop, uint8_t *sw1, uint8_t *sw2) {
    uint8_t data[16];
    uint8_t data_len = 0;
    
    // Default property if not provided: 8F 95 F0 FF FF
    const uint8_t default_prop[5] = {0x8F, 0x95, 0xF0, 0xFF, 0xFF};
    const uint8_t *use_prop = prop ? prop : default_prop;
    
    data[data_len++] = FMCOS_FILE_KEY;  // 0x3F
    data[data_len++] = slots;
    memcpy(data + data_len, use_prop, 5);
    data_len += 5;
    
    return fmcos_send_apdu(FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, 0x00, 0x00, data, data_len, 0, NULL, NULL, sw1, sw2);
}

// Create Binary EF
// Data: Type(0x28) + Size(2) + Perm(5)
int fmcos_create_binary_ef(uint16_t fid, uint16_t size, const uint8_t *perm, uint8_t *sw1, uint8_t *sw2) {
    uint8_t data[16];
    uint8_t data_len = 0;
    
    // Default permissions: FF FF FF FF FF
    const uint8_t default_perm[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t *use_perm = perm ? perm : default_perm;
    
    data[data_len++] = FMCOS_FILE_BINARY;  // 0x28
    data[data_len++] = (size >> 8) & 0xFF;
    data[data_len++] = size & 0xFF;
    memcpy(data + data_len, use_perm, 5);
    data_len += 5;
    
    uint8_t p1 = (fid >> 8) & 0xFF;
    uint8_t p2 = fid & 0xFF;
    return fmcos_send_apdu(FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, p1, p2, data, data_len, 0, NULL, NULL, sw1, sw2);
}

// Create Record EF (fixed, variable, or cyclic)
// Data: Type + SFI + Count + Len + Perm(5)
int fmcos_create_record_ef(uint16_t fid, uint8_t rec_type, uint8_t sfi, uint8_t count, uint8_t len,
                           const uint8_t *perm, uint8_t *sw1, uint8_t *sw2) {
    uint8_t data[16];
    uint8_t data_len = 0;
    
    // Default permissions: FF FF FF FF FF
    const uint8_t default_perm[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t *use_perm = perm ? perm : default_perm;
    
    data[data_len++] = rec_type;  // 0x2A, 0x2C, or 0x2E
    data[data_len++] = sfi;
    data[data_len++] = count;
    data[data_len++] = len;
    memcpy(data + data_len, use_perm, 5);
    data_len += 5;
    
    uint8_t p1 = (fid >> 8) & 0xFF;
    uint8_t p2 = fid & 0xFF;
    return fmcos_send_apdu(FMCOS_CLA_PBOC, FMCOS_INS_CREATE_FILE, p1, p2, data, data_len, 0, NULL, NULL, sw1, sw2);
}

// Drop field helper
void fmcos_drop_field(void) {
    DropField();
    g_fmcos_field_on = false;
}

// Info command using new helpers
int fmcos_info(void) {
    uint8_t sw1, sw2;
    PrintAndLogEx(INFO, "Selecting MF (3F00)...");
    
    uint8_t resp[256];
    uint16_t resplen = sizeof(resp);
    
    int ret = fmcos_select_file(0x3F00, resp, &resplen, &sw1, &sw2);
    
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Comms failed");
        return ret;
    }
    
    PrintAndLogEx(INFO, "Select SW: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
    
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(INFO, "FCI Length: %d", resplen);
        char hex[512] = {0};
        for(int i=0; i<resplen; i++) sprintf(hex+i*2, "%02X", resp[i]);
        PrintAndLogEx(INFO, "FCI: %s", hex);
    }
    
    return PM3_SUCCESS;
}
