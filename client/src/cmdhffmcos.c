//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// High frequency FMCOS (FM1208/FM1280) command handlers
// CLI interface for FMCOS smart card operations
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "pm3_cmd.h"
#include "cmdhffmcos.h"
#include "fmcos/fmcos.h"
#include "cliparser.h"
#include "cmdtrace.h"
#include "cmdparser.h"
#include "ui.h"
#include <string.h>
#include <stdlib.h>

//-----------------------------------------------------------------------------
// Helper Functions
//-----------------------------------------------------------------------------

/**
 * @brief Set verbose mode based on CLI argument.
 * @param ctx  CLI parser context.
 * @param idx  Argument index for verbose flag.
 */
static void handle_verbose(CLIParserContext *ctx, int idx) {
    if (arg_get_lit(ctx, idx)) {
        fmcos_set_verbose(true);
    } else {
        fmcos_set_verbose(false);
    }
}

//-----------------------------------------------------------------------------
// Command Handlers
//-----------------------------------------------------------------------------

/**
 * @brief hf fmcos select - Select file by FID.
 */
static int CmdHFFMCOSSelect(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "fid", "<hex>", "File ID (2 bytes)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos select", "Select File", "hf fmcos select -f 3F00");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable; // Silence unused variable warning

    // Indices: 0=begin, 1=fid, 2=verbose
    handle_verbose(ctx, 2);
    
    const char *fid_str = arg_get_str(ctx, 1)->sval[0];
    uint16_t fid = strtoul(fid_str, NULL, 16);
    
    uint8_t sw1, sw2;
    uint8_t resp[256];
    uint16_t resplen = sizeof(resp);
    
    int ret = fmcos_select_file(fid, resp, &resplen, &sw1, &sw2);
    
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Communication failed");
    } else {
        PrintAndLogEx(INFO, "Select SW: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
    }

    // Note: Do NOT drop field here - keep session active for subsequent commands
    CLIParserFree(ctx);
    return ret;
}

// hf fmcos read -o <offset> -l <len> [--sfi <sfi>] [-v]
static int CmdHFFMCOSRead(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1("o", "offset", "<int>", "Offset"),
        arg_int1("l", "len", "<int>", "Length"),
        arg_int0(NULL, "sfi", "<int>", "Short File Identifier"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos read", "Read Binary", "hf fmcos read -o 0 -l 16");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    // Indices: 0=begin, 1=off, 2=len, 3=sfi, 4=verbose
    handle_verbose(ctx, 4);
    
    int offset = arg_get_int(ctx, 1);
    int len = arg_get_int(ctx, 2);
    // Checking count for optional args is better but 0 defaults is acceptable for now
    int sfi = arg_get_int(ctx, 3);
    
    uint8_t *data = malloc(len);
    if (!data) return PM3_EMALLOC;

    uint8_t sw1, sw2;
    
    int ret = fmcos_read_binary((uint16_t)offset, (uint8_t)len, (uint8_t)sfi, data, &sw1, &sw2);
    
    if (ret == PM3_SUCCESS) {
        if (sw1 == 0x90 && sw2 == 0x00) {
            char hex[4096] = {0}; // Increased buffer
            // Safe hex dump (limit length)
            int dump_len = (len > 1024) ? 1024 : len;
            for(int i=0; i<dump_len; i++) sprintf(hex+i*2, "%02X", data[i]);
            PrintAndLogEx(INFO, "Data: %s%s", hex, len > 1024 ? "..." : "");
        } else {
            PrintAndLogEx(ERR, "Read failed: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
        }
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }
    
    free(data);
    CLIParserFree(ctx);
    return ret;
}

// hf fmcos update -o <offset> -d <data> [--sfi <sfi>] [-v]
static int CmdHFFMCOSUpdate(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1("o", "offset", "<int>", "Offset"),
        arg_str1("d", "data", "<hex>", "Data to write"),
        arg_int0(NULL, "sfi", "<int>", "Short File Identifier"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos update", "Update Binary", "hf fmcos update -o 0 -d AABBCC");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    // Indices: 0=begin, 1=off, 2=data, 3=sfi, 4=verbose
    handle_verbose(ctx, 4);
    
    int offset = arg_get_int(ctx, 1);
    const char *data_str = arg_get_str(ctx, 2)->sval[0];
    int sfi = arg_get_int(ctx, 3);
    
    uint8_t data[256];
    int len = 0;
    
    size_t slen = strlen(data_str);
    for (size_t i = 0; i < slen && len < 256; i += 2) {
        char byte_str[3] = {data_str[i], (i+1 < slen) ? data_str[i+1] : 0, 0};
        data[len++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    uint8_t sw1, sw2;
    int ret = fmcos_update_binary((uint16_t)offset, data, (uint8_t)len, (uint8_t)sfi, &sw1, &sw2);
    
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

static int CmdHFFMCOSInfo(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos info", "Get FMCOS card info", "hf fmcos info");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;
    
    // Indices: 0=begin, 1=verbose
    handle_verbose(ctx, 1);
    int ret = fmcos_info();
    CLIParserFree(ctx);
    return ret;
}

// hf fmcos auth --kid <kid> -k <key16> [-v]
static int CmdHFFMCOSAuth(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "kid", "<int>", "Key ID"),
        arg_str1("k", "key", "<hex>", "16-byte key (hex)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos auth", "External Authentication", "hf fmcos auth --kid 1 -k 00112233445566778899AABBCCDDEEFF");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 3);
    
    int kid = arg_get_int(ctx, 1);
    const char *key_str = arg_get_str(ctx, 2)->sval[0];
    
    uint8_t key[16];
    size_t slen = strlen(key_str);
    int keylen = 0;
    
    if (slen != 16 && slen != 32) {
        PrintAndLogEx(ERR, "Key must be 8 bytes (16 hex) or 16 bytes (32 hex)");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    for (size_t i = 0; i < slen; i += 2) {
        char byte_str[3] = {key_str[i], key_str[i+1], 0};
        key[keylen++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    int ret = fmcos_ext_auth((uint8_t)kid, key, (uint8_t)keylen);
    
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "External auth OK");
    } else {
        PrintAndLogEx(ERR, "External auth failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

// hf fmcos verify --kid <kid> --pin <pin> [-v]
static int CmdHFFMCOSVerify(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "kid", "<int>", "Key ID"),
        arg_str1(NULL, "pin", "<hex>", "PIN (hex)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos verify", "Verify PIN", "hf fmcos verify --kid 1 --pin 123456");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 3);
    
    int kid = arg_get_int(ctx, 1);
    const char *pin_str = arg_get_str(ctx, 2)->sval[0];
    
    uint8_t pin[16];
    size_t slen = strlen(pin_str);
    int pinlen = 0;
    for (size_t i = 0; i < slen && pinlen < 16; i += 2) {
        char byte_str[3] = {pin_str[i], (i+1 < slen) ? pin_str[i+1] : 0, 0};
        pin[pinlen++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    int ret = fmcos_verify_pin((uint8_t)kid, pin, (uint8_t)pinlen);
    
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Verify OK");
    } else {
        PrintAndLogEx(ERR, "Verify failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

// hf fmcos challenge -l <len> [-v]
static int CmdHFFMCOSChallenge(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int0("l", "len", "<int>", "Length (default 8)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos challenge", "Get Challenge", "hf fmcos challenge -l 8");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 2);
    
    int len = arg_get_int_def(ctx, 1, 8);
    
    uint8_t challenge[32] = {0};
    int ret = fmcos_get_challenge((uint8_t)len, challenge);
    
    if (ret == PM3_SUCCESS) {
        char hex[128] = {0};
        for(int i=0; i<len; i++) sprintf(hex+i*2, "%02X", challenge[i]);
        PrintAndLogEx(SUCCESS, "Challenge: %s", hex);
    } else {
        PrintAndLogEx(ERR, "Get challenge failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

// hf fmcos createdf -f <fid> --space <code> [--name <hex>] [--perm <hex>] [-v]
static int CmdHFFMCOSCreateDF(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "fid", "<hex>", "File ID (2 bytes)"),
        arg_int0(NULL, "space", "<int>", "Space code (default: 8)"),
        arg_str0(NULL, "name", "<hex>", "DF name (optional)"),
        arg_str0(NULL, "perm", "<hex>", "Permissions 5 bytes (optional)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos createdf", "Create DF", "hf fmcos createdf -f 3F01 --space 8");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 5);

    const char *fid_str = arg_get_str(ctx, 1)->sval[0];
    int space = arg_get_int_def(ctx, 2, 8);
    
    uint8_t df_name[16] = {0};
    uint8_t name_len = 0;
    struct arg_str *name_arg = arg_get_str(ctx, 3);
    if (name_arg->count > 0) {
        const char *name_str = name_arg->sval[0];
        size_t slen = strlen(name_str);
        for (size_t i = 0; i < slen && name_len < 16; i += 2) {
            char byte_str[3] = {name_str[i], name_str[i+1], 0};
            df_name[name_len++] = (uint8_t)strtoul(byte_str, NULL, 16);
        }
    }
    
    uint8_t perm[5] = {0};
    uint8_t *perm_ptr = NULL;
    struct arg_str *perm_arg = arg_get_str(ctx, 4);
    if (perm_arg->count > 0) {
        const char *perm_str = perm_arg->sval[0];
        for (int i = 0; i < 5 && perm_str[i*2]; i++) {
            char byte_str[3] = {perm_str[i*2], perm_str[i*2+1], 0};
            perm[i] = (uint8_t)strtoul(byte_str, NULL, 16);
        }
        perm_ptr = perm;
    }

    uint16_t fid = strtoul(fid_str, NULL, 16);
    uint8_t sw1, sw2;
    int ret = fmcos_create_df(fid, (uint8_t)space, name_len > 0 ? df_name : NULL, name_len, perm_ptr, &sw1, &sw2);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
        if (sw1 == 0x90 && sw2 == 0x00) PrintAndLogEx(SUCCESS, "DF created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

// hf fmcos createkey --slots <n> [--prop <hex>] [-v]
static int CmdHFFMCOSCreateKey(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "slots", "<int>", "Number of key slots"),
        arg_str0(NULL, "prop", "<hex>", "Property 5 bytes (optional)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos createkey", "Create Key File", "hf fmcos createkey --slots 8");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 3);

    int slots = arg_get_int(ctx, 1);
    
    uint8_t prop[5] = {0};
    uint8_t *prop_ptr = NULL;
    struct arg_str *prop_arg = arg_get_str(ctx, 2);
    if (prop_arg->count > 0) {
        const char *prop_str = prop_arg->sval[0];
        for (int i = 0; i < 5 && prop_str[i*2]; i++) {
            char byte_str[3] = {prop_str[i*2], prop_str[i*2+1], 0};
            prop[i] = (uint8_t)strtoul(byte_str, NULL, 16);
        }
        prop_ptr = prop;
    }

    uint8_t sw1, sw2;
    int ret = fmcos_create_key_file((uint8_t)slots, prop_ptr, &sw1, &sw2);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
        if (sw1 == 0x90 && sw2 == 0x00) PrintAndLogEx(SUCCESS, "Key file created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

// hf fmcos createbin -f <fid> --size <n> [--perm <hex>] [-v]
static int CmdHFFMCOSCreateBin(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "fid", "<hex>", "File ID (2 bytes)"),
        arg_int1(NULL, "size", "<int>", "Size in bytes"),
        arg_str0(NULL, "perm", "<hex>", "Permissions 5 bytes (optional)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos createbin", "Create Binary EF", "hf fmcos createbin -f 0001 --size 256");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 4);

    const char *fid_str = arg_get_str(ctx, 1)->sval[0];
    int size = arg_get_int(ctx, 2);
    
    uint8_t perm[5] = {0};
    uint8_t *perm_ptr = NULL;
    struct arg_str *perm_arg = arg_get_str(ctx, 3);
    if (perm_arg->count > 0) {
        const char *perm_str = perm_arg->sval[0];
        for (int i = 0; i < 5 && perm_str[i*2]; i++) {
            char byte_str[3] = {perm_str[i*2], perm_str[i*2+1], 0};
            perm[i] = (uint8_t)strtoul(byte_str, NULL, 16);
        }
        perm_ptr = perm;
    }

    uint16_t fid = strtoul(fid_str, NULL, 16);
    uint8_t sw1, sw2;
    int ret = fmcos_create_binary_ef(fid, (uint16_t)size, perm_ptr, &sw1, &sw2);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
        if (sw1 == 0x90 && sw2 == 0x00) PrintAndLogEx(SUCCESS, "Binary EF created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

// hf fmcos createrec -f <fid> --type <fixed|variable|cyclic> --len <n> --count <n> [--sfi <n>] [--perm <hex>] [-v]
static int CmdHFFMCOSCreateRec(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "fid", "<hex>", "File ID (2 bytes)"),
        arg_str1(NULL, "type", "<fixed|variable|cyclic>", "Record type"),
        arg_int1(NULL, "len", "<int>", "Record length"),
        arg_int0(NULL, "count", "<int>", "Record count (default: 10)"),
        arg_int0(NULL, "sfi", "<int>", "SFI (default: 1)"),
        arg_str0(NULL, "perm", "<hex>", "Permissions 5 bytes (optional)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos createrec", "Create Record EF", "hf fmcos createrec -f 0002 --type fixed --len 32 --count 10");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 7);

    const char *fid_str = arg_get_str(ctx, 1)->sval[0];
    const char *type_str = arg_get_str(ctx, 2)->sval[0];
    int rec_len = arg_get_int(ctx, 3);
    int rec_count = arg_get_int_def(ctx, 4, 10);
    int sfi = arg_get_int_def(ctx, 5, 1);
    
    uint8_t rec_type;
    if (strcmp(type_str, "fixed") == 0) {
        rec_type = FMCOS_FILE_FIXED_REC;
    } else if (strcmp(type_str, "variable") == 0) {
        rec_type = FMCOS_FILE_VAR_REC;
    } else if (strcmp(type_str, "cyclic") == 0) {
        rec_type = FMCOS_FILE_CYCLIC_REC;
    } else {
        PrintAndLogEx(ERR, "Unknown record type: %s", type_str);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    
    uint8_t perm[5] = {0};
    uint8_t *perm_ptr = NULL;
    struct arg_str *perm_arg = arg_get_str(ctx, 6);
    if (perm_arg->count > 0) {
        const char *perm_str = perm_arg->sval[0];
        for (int i = 0; i < 5 && perm_str[i*2]; i++) {
            char byte_str[3] = {perm_str[i*2], perm_str[i*2+1], 0};
            perm[i] = (uint8_t)strtoul(byte_str, NULL, 16);
        }
        perm_ptr = perm;
    }

    uint16_t fid = strtoul(fid_str, NULL, 16);
    uint8_t sw1, sw2;
    int ret = fmcos_create_record_ef(fid, rec_type, (uint8_t)sfi, (uint8_t)rec_count, (uint8_t)rec_len, perm_ptr, &sw1, &sw2);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", sw1, sw2, fmcos_get_sw_desc(sw1, sw2));
        if (sw1 == 0x90 && sw2 == 0x00) PrintAndLogEx(SUCCESS, "Record EF created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

// ---------------------------------------------------------------------------
// hf fmcos explore [--mode ef|df] [--start XXXX] [--end XXXX] [-v]
// Scans file system for EFs or DFs in given range
// ---------------------------------------------------------------------------
static const char* fmcos_file_type_name(uint8_t type_byte) {
    switch (type_byte) {
        case 0x38: return "DF";
        case 0x28: return "Binary EF";
        case 0x2A: return "Fixed Record EF";
        case 0x2C: return "Variable Record EF";
        case 0x2E: return "Cyclic Record EF";
        case 0x2F: return "Wallet/E-Purse";
        case 0x3F: return "Key File";
        case 0x6F: return "DF (FCI)";
        default:   return "Unknown";
    }
}

static int CmdHFFMCOSExplore(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "mode", "<ef|df>", "Scan mode: 'ef' (default) or 'df'"),
        arg_str0(NULL, "start", "<hex>", "Start FID (default: 0000 for ef, DF01 for df)"),
        arg_str0(NULL, "end", "<hex>", "End FID (default: 0020 for ef, DF10 for df)"),
        arg_str0(NULL, "base", "<hex>", "Base DF to return to (default: 3F00)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos explore",
        "Scan file system for EFs or DFs in given FID range",
        "hf fmcos explore\n"
        "hf fmcos explore --mode df --start DF01 --end DF20\n"
        "hf fmcos explore --start 0001 --end 00FF -v");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    // Parse arguments
    handle_verbose(ctx, 5);

    // Mode
    bool df_mode = false;
    struct arg_str *mode_arg = arg_get_str(ctx, 1);
    if (mode_arg->count > 0) {
        const char *mode_str = mode_arg->sval[0];
        if (strcmp(mode_str, "df") == 0 || strcmp(mode_str, "DF") == 0) {
            df_mode = true;
        }
    }

    // Determine default range based on mode
    uint16_t start_fid, end_fid;
    if (df_mode) {
        start_fid = 0xDF01;
        end_fid = 0xDF10;
    } else {
        start_fid = 0x0000;
        end_fid = 0x0020;
    }

    // Override with user values if provided
    struct arg_str *start_arg = arg_get_str(ctx, 2);
    if (start_arg->count > 0) {
        start_fid = strtoul(start_arg->sval[0], NULL, 16);
    }
    struct arg_str *end_arg = arg_get_str(ctx, 3);
    if (end_arg->count > 0) {
        end_fid = strtoul(end_arg->sval[0], NULL, 16);
    }

    // Base FID to return to after each select
    uint16_t base_fid = 0x3F00;
    struct arg_str *base_arg = arg_get_str(ctx, 4);
    if (base_arg->count > 0) {
        base_fid = strtoul(base_arg->sval[0], NULL, 16);
    }

    CLIParserFree(ctx);

    // Print header
    PrintAndLogEx(INFO, "Exploring %s Range %04X-%04X...", df_mode ? "DF" : "EF", start_fid, end_fid);
    PrintAndLogEx(INFO, "------------------------------------------------------------");
    PrintAndLogEx(INFO, "%-6s %-18s %-6s %-30s", "FID", "Type", "Size", "Info");
    PrintAndLogEx(INFO, "------------------------------------------------------------");

    int found_count = 0;
    uint8_t resp[256];
    uint16_t resplen;
    uint8_t sw1, sw2;

    for (uint32_t fid = start_fid; fid <= end_fid; fid++) {
        resplen = sizeof(resp);
        int ret = fmcos_select_file((uint16_t)fid, resp, &resplen, &sw1, &sw2);

        if (ret == PM3_SUCCESS && sw1 == 0x90 && sw2 == 0x00) {
            found_count++;

            const char *type_str = "Unknown";
            char size_str[16] = "-";
            char info_str[64] = "";

            // Parse FCI response
            if (resplen >= 1) {
                uint8_t type_byte = resp[0];
                type_str = fmcos_file_type_name(type_byte);

                // Try to extract size (bytes 1-2 for some types)
                if (resplen >= 3 && type_byte != 0x6F && type_byte != 0x38) {
                    uint16_t size_val = (resp[1] << 8) | resp[2];
                    snprintf(size_str, sizeof(size_str), "%u", size_val);
                }

                // For DFs (0x38 or 0x6F), try to extract name from tag 84
                if (type_byte == 0x38 || type_byte == 0x6F) {
                    // Search for tag 84 in response
                    for (int i = 0; i < (int)resplen - 2; i++) {
                        if (resp[i] == 0x84) {
                            uint8_t name_len = resp[i + 1];
                            if (name_len > 0 && i + 2 + name_len <= (int)resplen) {
                                // Convert hex name to ASCII if printable
                                char name_buf[32] = {0};
                                int pos = 0;
                                for (int j = 0; j < name_len && pos < 30; j++) {
                                    uint8_t c = resp[i + 2 + j];
                                    if (c >= 0x20 && c < 0x7F) {
                                        name_buf[pos++] = c;
                                    }
                                }
                                if (pos > 0) {
                                    snprintf(info_str, sizeof(info_str), "Name: %s", name_buf);
                                }
                            }
                            break;
                        }
                    }
                }
            }

            // Fallback probing if type is still Unknown (no FCI or unrecognized type)
            if (strcmp(type_str, "Unknown") == 0) {
                uint8_t probe_data[4];
                uint8_t probe_sw1, probe_sw2;
                
                // Try READ BINARY (offset 0, length 1)
                int probe_ret = fmcos_read_binary(0, 1, 0, probe_data, &probe_sw1, &probe_sw2);
                if (probe_ret == PM3_SUCCESS && probe_sw1 == 0x90 && probe_sw2 == 0x00) {
                    type_str = "Binary EF (probe)";
                } else if (probe_sw1 == 0x69 && probe_sw2 == 0x86) {
                    // 6986 = Command not allowed (no current EF selected) = likely DF
                    type_str = "DF (probe)";
                } else {
                    // Try READ RECORD (record 1)
                    // Note: We don't have fmcos_read_record implemented yet
                    // For now just mark as EF if READ BINARY failed with security error
                    if (probe_sw1 == 0x69 && probe_sw2 == 0x82) {
                        // 6982 = Security status not satisfied = likely protected EF
                        type_str = "EF (protected)";
                    }
                }
                
                // Re-select the file after probe (probe might have changed state)
                resplen = sizeof(resp);
                fmcos_select_file((uint16_t)fid, resp, &resplen, &sw1, &sw2);
            }

            PrintAndLogEx(SUCCESS, "%04X   %-18s %-6s %-30s", fid, type_str, size_str, info_str);

            // Return to base DF for next iteration
            resplen = sizeof(resp);
            fmcos_select_file(base_fid, resp, &resplen, &sw1, &sw2);
        }
    }

    PrintAndLogEx(INFO, "------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "Found %d files", found_count);

    fmcos_drop_field();
    return PM3_SUCCESS;
}

/**
 * @brief hf fmcos off - Drop RF field and terminate session.
 */
static int CmdHFFMCOSOff(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos off",
        "Drop RF field and terminate session",
        "hf fmcos off");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;
    CLIParserFree(ctx);

    fmcos_drop_field();
    PrintAndLogEx(SUCCESS, "RF field dropped, session terminated");
    return PM3_SUCCESS;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help", CmdHelp, AlwaysAvailable, "This help"},
    {"info", CmdHFFMCOSInfo, AlwaysAvailable, "Get card info"},
    {"off", CmdHFFMCOSOff, AlwaysAvailable, "Drop RF field / terminate session"},
    {"select", CmdHFFMCOSSelect, AlwaysAvailable, "Select file"},
    {"read", CmdHFFMCOSRead, AlwaysAvailable, "Read binary"},
    {"update", CmdHFFMCOSUpdate, AlwaysAvailable, "Update binary"},
    {"createdf", CmdHFFMCOSCreateDF, AlwaysAvailable, "Create DF"},
    {"createkey", CmdHFFMCOSCreateKey, AlwaysAvailable, "Create Key File"},
    {"createbin", CmdHFFMCOSCreateBin, AlwaysAvailable, "Create Binary EF"},
    {"createrec", CmdHFFMCOSCreateRec, AlwaysAvailable, "Create Record EF"},
    {"auth", CmdHFFMCOSAuth, AlwaysAvailable, "External authentication"},
    {"verify", CmdHFFMCOSVerify, AlwaysAvailable, "Verify PIN"},
    {"challenge", CmdHFFMCOSChallenge, AlwaysAvailable, "Get challenge"},
    {"explore", CmdHFFMCOSExplore, AlwaysAvailable, "Explore file system"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFFMCOS(const char *Cmd) {
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
