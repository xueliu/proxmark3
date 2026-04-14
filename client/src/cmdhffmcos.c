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
// High frequency FMCOS (FM1208/FM1280) command handlers
// CLI interface for FMCOS smart card operations
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "pm3_cmd.h"
#include "cmdhffmcos.h"
#include "fmcos/fmcos.h"
#include "fmcos/fmcos_core.h"
#include "fmcos/fmcos_status.h"
#include "cliparser.h"
#include "cmdtrace.h"
#include "cmdparser.h"
#include "ui.h"
#include <string.h>
#include <stdlib.h>

// Global context to retain state between commands
static fmcos_session_t g_fmcos_cli_session;

//-----------------------------------------------------------------------------
// Helper Functions
//-----------------------------------------------------------------------------

static void handle_verbose(CLIParserContext *ctx, int idx) {
    if (arg_get_lit(ctx, idx)) {
        g_fmcos_cli_session.verbose = true;
    } else {
        g_fmcos_cli_session.verbose = false;
    }
}

//-----------------------------------------------------------------------------
// Command Handlers
//-----------------------------------------------------------------------------

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
    (void)argtable;

    handle_verbose(ctx, 2);
    
    const char *fid_str = arg_get_str(ctx, 1)->sval[0];
    uint16_t fid = strtoul(fid_str, NULL, 16);
    
    fmcos_resp_t resp;
    int ret = fmcos_cmd_select_file(&g_fmcos_cli_session, fid, &resp);
    
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Communication failed");
    } else {
        PrintAndLogEx(INFO, "Select SW: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
    }

    CLIParserFree(ctx);
    return ret;
}

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

    handle_verbose(ctx, 4);
    
    int offset = arg_get_int(ctx, 1);
    int len = arg_get_int(ctx, 2);
    int sfi = arg_get_int(ctx, 3);
    
    fmcos_resp_t resp;
    int ret = fmcos_cmd_read_binary(&g_fmcos_cli_session, (uint16_t)offset, (uint8_t)len, (uint8_t)sfi, &resp);
    
    if (ret == PM3_SUCCESS) {
        if (resp.sw1 == 0x90 && resp.sw2 == 0x00) {
            char hex[4096] = {0};
            int dump_len = (resp.data_len > 1024) ? 1024 : resp.data_len;
            for(int i=0; i<dump_len; i++) sprintf(hex+i*2, "%02X", resp.data[i]);
            PrintAndLogEx(INFO, "Data: %s%s", hex, resp.data_len > 1024 ? "..." : "");
        } else {
            PrintAndLogEx(ERR, "Read failed: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
        }
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

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
    
    fmcos_resp_t resp;
    int ret = fmcos_cmd_update_binary(&g_fmcos_cli_session, (uint16_t)offset, data, (uint8_t)len, (uint8_t)sfi, &resp);
    
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
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
    
    handle_verbose(ctx, 1);
    int ret = fmcos_info(&g_fmcos_cli_session);
    CLIParserFree(ctx);
    return ret;
}

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
    
    fmcos_resp_t resp;
    int ret = fmcos_cmd_ext_auth(&g_fmcos_cli_session, (uint8_t)kid, key, (uint8_t)keylen, &resp);
    
    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        PrintAndLogEx(SUCCESS, "External auth OK");
    } else {
        PrintAndLogEx(ERR, "External auth failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

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
    
    fmcos_resp_t resp;
    int ret = fmcos_cmd_verify_pin(&g_fmcos_cli_session, (uint8_t)kid, pin, (uint8_t)pinlen, &resp);
    
    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        PrintAndLogEx(SUCCESS, "Verify OK");
    } else {
        PrintAndLogEx(ERR, "Verify failed: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
    }
    
    CLIParserFree(ctx);
    return ret;
}

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
    
    fmcos_resp_t resp;
    int ret = fmcos_cmd_get_challenge(&g_fmcos_cli_session, (uint8_t)len, &resp);
    
    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        char hex[128] = {0};
        for(size_t i=0; i<resp.data_len; i++) sprintf(hex+i*2, "%02X", resp.data[i]);
        PrintAndLogEx(SUCCESS, "Challenge: %s", hex);
    } else {
        PrintAndLogEx(ERR, "Get challenge failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

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
    fmcos_resp_t resp;
    int ret = fmcos_cmd_create_df(&g_fmcos_cli_session, fid, (uint8_t)space, name_len > 0 ? df_name : NULL, name_len, perm_ptr, &resp);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
        if (resp.sw1 == 0x90 && resp.sw2 == 0x00) PrintAndLogEx(SUCCESS, "DF created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

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

    fmcos_resp_t resp;
    int ret = fmcos_cmd_create_key_file(&g_fmcos_cli_session, (uint8_t)slots, prop_ptr, &resp);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
        if (resp.sw1 == 0x90 && resp.sw2 == 0x00) PrintAndLogEx(SUCCESS, "Key file created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

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
    fmcos_resp_t resp;
    int ret = fmcos_cmd_create_binary_ef(&g_fmcos_cli_session, fid, (uint16_t)size, perm_ptr, &resp);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
        if (resp.sw1 == 0x90 && resp.sw2 == 0x00) PrintAndLogEx(SUCCESS, "Binary EF created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

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
    fmcos_resp_t resp;
    int ret = fmcos_cmd_create_record_ef(&g_fmcos_cli_session, fid, rec_type, (uint8_t)sfi, (uint8_t)rec_count, (uint8_t)rec_len, perm_ptr, &resp);

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "SW: %02X%02X (%s)", resp.sw1, resp.sw2, fmcos_status_to_string(resp.sw1, resp.sw2));
        if (resp.sw1 == 0x90 && resp.sw2 == 0x00) PrintAndLogEx(SUCCESS, "Record EF created");
    } else {
        PrintAndLogEx(ERR, "Communication failed");
    }

    CLIParserFree(ctx);
    return ret;
}

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

    handle_verbose(ctx, 5);

    bool df_mode = false;
    struct arg_str *mode_arg = arg_get_str(ctx, 1);
    if (mode_arg->count > 0) {
        const char *mode_str = mode_arg->sval[0];
        if (strcmp(mode_str, "df") == 0 || strcmp(mode_str, "DF") == 0) {
            df_mode = true;
        }
    }

    uint16_t start_fid, end_fid;
    if (df_mode) {
        start_fid = 0xDF01;
        end_fid = 0xDF10;
    } else {
        start_fid = 0x0000;
        end_fid = 0x0020;
    }

    struct arg_str *start_arg = arg_get_str(ctx, 2);
    if (start_arg->count > 0) {
        start_fid = strtoul(start_arg->sval[0], NULL, 16);
    }
    struct arg_str *end_arg = arg_get_str(ctx, 3);
    if (end_arg->count > 0) {
        end_fid = strtoul(end_arg->sval[0], NULL, 16);
    }

    uint16_t base_fid = 0x3F00;
    struct arg_str *base_arg = arg_get_str(ctx, 4);
    if (base_arg->count > 0) {
        base_fid = strtoul(base_arg->sval[0], NULL, 16);
    }

    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Exploring %s Range %04X-%04X...", df_mode ? "DF" : "EF", start_fid, end_fid);
    PrintAndLogEx(INFO, "------------------------------------------------------------");
    PrintAndLogEx(INFO, "%-6s %-18s %-6s %-30s", "FID", "Type", "Size", "Info");
    PrintAndLogEx(INFO, "------------------------------------------------------------");

    int found_count = 0;
    fmcos_resp_t resp;

    for (uint32_t fid = start_fid; fid <= end_fid; fid++) {
        int ret = fmcos_cmd_select_file(&g_fmcos_cli_session, (uint16_t)fid, &resp);

        if (ret == PM3_SUCCESS && resp.sw1 == 0x90 && resp.sw2 == 0x00) {
            found_count++;

            const char *type_str = "Unknown";
            char size_str[16] = "-";
            char info_str[64] = "";

            if (resp.data_len >= 1) {
                uint8_t type_byte = resp.data[0];
                type_str = fmcos_file_type_name(type_byte);

                if (resp.data_len >= 3 && type_byte != 0x6F && type_byte != 0x38) {
                    uint16_t size_val = (resp.data[1] << 8) | resp.data[2];
                    snprintf(size_str, sizeof(size_str), "%u", size_val);
                }

                if (type_byte == 0x38 || type_byte == 0x6F) {
                    for (int i = 0; i < (int)resp.data_len - 2; i++) {
                        if (resp.data[i] == 0x84) {
                            uint8_t name_len = resp.data[i + 1];
                            if (name_len > 0 && i + 2 + name_len <= (int)resp.data_len) {
                                char name_buf[32] = {0};
                                int pos = 0;
                                for (int j = 0; j < name_len && pos < 30; j++) {
                                    uint8_t c = resp.data[i + 2 + j];
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

            if (strcmp(type_str, "Unknown") == 0) {
                fmcos_resp_t probe_resp;
                
                int probe_ret = fmcos_cmd_read_binary(&g_fmcos_cli_session, 0, 1, 0, &probe_resp);
                if (probe_ret == PM3_SUCCESS && probe_resp.sw1 == 0x90 && probe_resp.sw2 == 0x00) {
                    type_str = "Binary EF (probe)";
                } else if (probe_resp.sw1 == 0x69 && probe_resp.sw2 == 0x86) {
                    type_str = "DF (probe)";
                } else if (probe_resp.sw1 == 0x69 && probe_resp.sw2 == 0x82) {
                    type_str = "EF (protected)";
                } else {
                    probe_ret = fmcos_cmd_read_record(&g_fmcos_cli_session, 1, 0, &probe_resp);
                    if (probe_ret == PM3_SUCCESS && probe_resp.sw1 == 0x90 && probe_resp.sw2 == 0x00) {
                        type_str = "Record EF (probe)";
                    } else if (probe_resp.sw1 == 0x69 && probe_resp.sw2 == 0x82) {
                        type_str = "Record EF (protected)";
                    } else {
                        uint32_t balance;
                        probe_ret = fmcos_cmd_get_balance(&g_fmcos_cli_session, 0x02, &balance);
                        if (probe_ret == PM3_SUCCESS) {
                            type_str = "Wallet (probe)";
                            snprintf(info_str, sizeof(info_str), "Balance: %u", balance);
                        }
                    }
                }
                
                fmcos_cmd_select_file(&g_fmcos_cli_session, (uint16_t)fid, &resp);
            }

            PrintAndLogEx(SUCCESS, "%04X   %-18s %-6s %-30s", fid, type_str, size_str, info_str);
            fmcos_cmd_select_file(&g_fmcos_cli_session, base_fid, &resp);
        }
    }

    PrintAndLogEx(INFO, "------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "Found %d files", found_count);

    fmcos_session_drop_field(&g_fmcos_cli_session);
    return PM3_SUCCESS;
}

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

    fmcos_session_drop_field(&g_fmcos_cli_session);
    PrintAndLogEx(SUCCESS, "RF field dropped, session terminated");
    return PM3_SUCCESS;
}

static int CmdHFFMCOSWriteKey(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "kid", "<int>", "Key ID"),
        arg_int1("t", "type", "<int>", "Key Type"),
        arg_int0("a", "add", "<0|1>", "0: update, 1: add (default: 1)"),
        arg_str1("d", "data", "<hex>", "Payload (Rights + key data)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos writekey", "Write/Update Key", "hf fmcos writekey --kid 0 -t 36 -a 1 -d F0F40598C4608B786AF1992343E91A076670AE7C");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    handle_verbose(ctx, 5);
    
    int kid = arg_get_int(ctx, 1);
    int ktype = arg_get_int(ctx, 2);
    int is_add = 1;
    if (arg_get_int_count(ctx, 3) > 0) is_add = arg_get_int(ctx, 3);
    const char *data_str = arg_get_str(ctx, 4)->sval[0];
    
    uint8_t data[64];
    size_t slen = strlen(data_str);
    int datalen = 0;
    for (size_t i = 0; i < slen && datalen < 64; i += 2) {
        char byte_str[3] = {data_str[i], (i+1 < slen) ? data_str[i+1] : 0, 0};
        data[datalen++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    fmcos_resp_t resp;
    int ret = fmcos_cmd_write_key(&g_fmcos_cli_session, is_add, ktype, kid, data, datalen, &resp);
    
    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        PrintAndLogEx(SUCCESS, "Write Key OK");
    } else {
        PrintAndLogEx(ERR, "Write Key failed (SW: %02X%02X)", resp.sw1, resp.sw2);
    }
    CLIParserFree(ctx);
    return ret;
}

static int CmdHFFMCOSBalance(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "app", "<1|2>", "1: ED/Passbook, 2: Wallet (default: 2)"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos balance", "Get Balance", "hf fmcos balance --app 2");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    int app_type = 2;
    if (arg_get_int_count(ctx, 1) > 0) app_type = arg_get_int(ctx, 1);
    
    uint32_t balance = 0;
    int ret = fmcos_cmd_get_balance(&g_fmcos_cli_session, app_type, &balance);
    
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Balance (%s): %u", app_type == 1 ? "EP" : "Wallet", balance);
    } else {
        PrintAndLogEx(ERR, "Get Balance failed");
    }
    CLIParserFree(ctx);
    return ret;
}

static int CmdHFFMCOSLoad(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1("k", "kid", "<int>", "Key ID"),
        arg_int0("a", "app", "<1|2>", "1: EP, 2: Wallet (default: 2)"),
        arg_int1("v", "amt", "<int>", "Amount to Load"),
        arg_str1("t", "term", "<hex>", "Terminal ID (6 bytes hex)"),
        arg_str1("m", "mkey", "<hex>", "Master Key (16 bytes hex)"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos load", "Load PBOC E-Deposit", "hf fmcos load --kid 0 --app 2 --amt 1000 --term 666666666666 --mkey A9E6E145F5DF09500A58EEF8575D49DB");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    int kid = arg_get_int(ctx, 1);
    int app_type = 2;
    if (arg_get_int_count(ctx, 2) > 0) app_type = arg_get_int(ctx, 2);
    int amt_val = arg_get_int(ctx, 3);
    const char *term_str = arg_get_str(ctx, 4)->sval[0];
    const char *mkey_str = arg_get_str(ctx, 5)->sval[0];
    
    uint8_t amt[4] = { (amt_val >> 24) & 0xFF, (amt_val >> 16) & 0xFF, (amt_val >> 8) & 0xFF, amt_val & 0xFF };
    
    uint8_t term[6] = {0};
    for (size_t i = 0; i < strlen(term_str) && i < 12; i += 2) {
        char byte_str[3] = {term_str[i], (i+1 < strlen(term_str)) ? term_str[i+1] : 0, 0};
        term[i/2] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    uint8_t mkey[16] = {0};
    for (size_t i = 0; i < strlen(mkey_str) && i < 32; i += 2) {
        char byte_str[3] = {mkey_str[i], (i+1 < strlen(mkey_str)) ? mkey_str[i+1] : 0, 0};
        mkey[i/2] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    int ret = fmcos_txn_init_load(&g_fmcos_cli_session, kid, app_type, amt, term, mkey, 16);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Init Load failed");
        CLIParserFree(ctx);
        return ret;
    }
    PrintAndLogEx(INFO, "MAC1 Verified!");
    
    uint8_t dummy_date[4] = {0x20, 0x26, 0x04, 0x13};
    uint8_t dummy_time[3] = {0x12, 0x00, 0x00};
    
    ret = fmcos_txn_credit(&g_fmcos_cli_session, dummy_date, dummy_time);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Credit Load OK. Wallet Updated.");
    } else {
        PrintAndLogEx(ERR, "Credit Load failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

static int CmdHFFMCOSPurchase(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_int1("k", "kid", "<int>", "Key ID"),
        arg_int0("a", "app", "<1|2>", "1: EP, 2: Wallet (default: 2)"),
        arg_int1("v", "amt", "<int>", "Amount to Purchase"),
        arg_str1("t", "term", "<hex>", "Terminal ID (6 bytes hex)"),
        arg_str1("m", "mkey", "<hex>", "Master Key (16 bytes hex)"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos purchase", "Purchase PBOC E-Deposit", "hf fmcos purchase --kid 0 --app 2 --amt 50 --term 666666666666 --mkey EB18CE6986C820970E876219052CE0CF");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    int kid = arg_get_int(ctx, 1);
    int app_type = 2;
    if (arg_get_int_count(ctx, 2) > 0) app_type = arg_get_int(ctx, 2);
    int amt_val = arg_get_int(ctx, 3);
    const char *term_str = arg_get_str(ctx, 4)->sval[0];
    const char *mkey_str = arg_get_str(ctx, 5)->sval[0];
    
    uint8_t amt[4] = { (amt_val >> 24) & 0xFF, (amt_val >> 16) & 0xFF, (amt_val >> 8) & 0xFF, amt_val & 0xFF };
    
    uint8_t term[6] = {0};
    for (size_t i = 0; i < strlen(term_str) && i < 12; i += 2) {
        char byte_str[3] = {term_str[i], (i+1 < strlen(term_str)) ? term_str[i+1] : 0, 0};
        term[i/2] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    uint8_t mkey[16] = {0};
    for (size_t i = 0; i < strlen(mkey_str) && i < 32; i += 2) {
        char byte_str[3] = {mkey_str[i], (i+1 < strlen(mkey_str)) ? mkey_str[i+1] : 0, 0};
        mkey[i/2] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    
    int ret = fmcos_txn_init_purchase(&g_fmcos_cli_session, kid, app_type, amt, term, mkey, 16);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Init Purchase failed");
        CLIParserFree(ctx);
        return ret;
    }
    PrintAndLogEx(INFO, "Purchase initialized!");
    
    uint8_t dummy_date[4] = {0x20, 0x26, 0x04, 0x13};
    uint8_t dummy_time[3] = {0x12, 0x00, 0x00};
    
    ret = fmcos_txn_debit(&g_fmcos_cli_session, dummy_date, dummy_time);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Debit OK.");
    } else {
        PrintAndLogEx(ERR, "Debit failed");
    }
    
    CLIParserFree(ctx);
    return ret;
}

static int CmdHFFMCOSPin(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_str1("o", "op", "<change|unblock|reload>", "PIN operation"),
        arg_int1("k", "kid", "<int>", "Key ID"),
        arg_str0("p", "pin", "<hex>", "Old or Blocked PIN"),
        arg_str1("n", "new", "<hex>", "New PIN"),
        arg_str0("m", "mkey", "<hex>", "Maintenance/Unblock Key"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos pin", "PIN Management", "hf fmcos pin --op change --kid 0 --pin 123456 --new 13371337");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    const char *op = arg_get_str(ctx, 1)->sval[0];
    int kid = arg_get_int(ctx, 2);
    
    struct arg_str *arg_pin = arg_get_str(ctx, 3);
    const char *pin_str = (arg_pin->count > 0) ? arg_pin->sval[0] : "";
    
    struct arg_str *arg_new = arg_get_str(ctx, 4);
    const char *new_str = (arg_new->count > 0) ? arg_new->sval[0] : "";
    
    struct arg_str *arg_mkey = arg_get_str(ctx, 5);
    const char *mkey_str = (arg_mkey->count > 0) ? arg_mkey->sval[0] : "";

    uint8_t pin[16] = {0}, newpin[16] = {0}, mkey[16] = {0};
    int pin_len = 0, new_len = 0, mkey_len = 0;

    size_t slen;
    slen = strlen(pin_str);
    for (size_t i = 0; i < slen && pin_len < 16; i += 2) {
        char byte_str[3] = {pin_str[i], (i+1 < slen) ? pin_str[i+1] : 0, 0};
        pin[pin_len++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }

    slen = strlen(new_str);
    for (size_t i = 0; i < slen && new_len < 16; i += 2) {
        char byte_str[3] = {new_str[i], (i+1 < slen) ? new_str[i+1] : 0, 0};
        newpin[new_len++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }

    slen = strlen(mkey_str);
    for (size_t i = 0; i < slen && mkey_len < 16; i += 2) {
        char byte_str[3] = {mkey_str[i], (i+1 < slen) ? mkey_str[i+1] : 0, 0};
        mkey[mkey_len++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }

    int ret = PM3_EINVARG;
    fmcos_resp_t resp;

    if (strcmp(op, "change") == 0) {
        ret = fmcos_cmd_change_pin(&g_fmcos_cli_session, kid, pin, newpin, new_len, &resp);
    } else if (strcmp(op, "unblock") == 0) {
        ret = fmcos_cmd_pin_unblock(&g_fmcos_cli_session, kid, newpin, new_len, mkey, mkey_len, &resp);
    } else if (strcmp(op, "reload") == 0) {
        ret = fmcos_cmd_reload_pin(&g_fmcos_cli_session, kid, newpin, new_len, mkey, mkey_len, &resp);
    } else {
        PrintAndLogEx(ERR, "Invalid operation");
    }

    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        PrintAndLogEx(SUCCESS, "PIN %s OK", op);
    } else if (ret == PM3_SUCCESS) {
        PrintAndLogEx(ERR, "PIN %s failed (SW1: %02X SW2: %02X)", op, resp.sw1, resp.sw2);
    }
    
    CLIParserFree(ctx);
    return ret;
}

static int CmdHFFMCOSLock(const char *Cmd) {
    CLIParserContext *ctx;
    void *argtable[] = {
        arg_param_begin,
        arg_str1("o", "op", "<card|app|unblock>", "Lock operation"),
        arg_str1("m", "mkey", "<hex>", "Maintenance Key"),
        arg_param_end
    };

    CLIParserInit(&ctx, "hf fmcos lock", "App/Card Locking", "hf fmcos lock --op app --mkey ...");
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    (void)argtable;

    const char *op = arg_get_str(ctx, 1)->sval[0];
    const char *mkey_str = arg_get_str(ctx, 2)->sval[0];
    
    uint8_t mkey[16];
    size_t slen = strlen(mkey_str);
    int mkey_len = 0;
    for (size_t i = 0; i < slen && mkey_len < 16; i += 2) {
        char byte_str[3] = {mkey_str[i], (i+1 < slen) ? mkey_str[i+1] : 0, 0};
        mkey[mkey_len++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }

    int ret = PM3_EINVARG;
    fmcos_resp_t resp;

    if (strcmp(op, "card") == 0) {
        ret = fmcos_cmd_card_block(&g_fmcos_cli_session, mkey, mkey_len, &resp);
    } else if (strcmp(op, "app") == 0) {
        ret = fmcos_cmd_app_block(&g_fmcos_cli_session, 0, mkey, mkey_len, &resp); // temporary block
    } else if (strcmp(op, "unblock") == 0) {
        ret = fmcos_cmd_app_unblock(&g_fmcos_cli_session, mkey, mkey_len, &resp);
    } else {
        PrintAndLogEx(ERR, "Invalid lock operation");
    }

    if (ret == PM3_SUCCESS && fmcos_status_is_ok(resp.sw1, resp.sw2)) {
        PrintAndLogEx(SUCCESS, "Lock %s OK", op);
    } else if (ret == PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Lock %s failed (SW1: %02X SW2: %02X)", op, resp.sw1, resp.sw2);
    }
    
    CLIParserFree(ctx);
    return ret;
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
    {"writekey", CmdHFFMCOSWriteKey, AlwaysAvailable, "Write/Update Key"},
    {"balance", CmdHFFMCOSBalance, AlwaysAvailable, "Get E-Deposit Balance"},
    {"load", CmdHFFMCOSLoad, AlwaysAvailable, "Load PBOC E-Deposit (Init + Credit)"},
    {"purchase", CmdHFFMCOSPurchase, AlwaysAvailable, "Purchase PBOC E-Deposit (Init + Debit)"},
    {"pin", CmdHFFMCOSPin, AlwaysAvailable, "Manage PINs (change, unblock, reload)"},
    {"lock", CmdHFFMCOSLock, AlwaysAvailable, "Lock/Unblock Application or Card"},
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
