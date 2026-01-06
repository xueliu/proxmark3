--[[
    FMCOS 2.0 Smart Card Library for Proxmark3 (Lua)

    This library provides core FMCOS 2.0 (FM1208/FM1280) smart card
    interface functions for use with the Proxmark3 Lua scripting environment.

    Session Control:
    - All functions accept `keep_field` parameter (default: true)
    - First command should use connect() to establish session
    - Last command should use disconnect() to release RF field

    Author: Xue Liu <liuxuenetmail@gmail.com>
    License: GPL-3.0
--]]

local cmds = require('commands')
local lib14a = require('read14a')
local utils = require('utils')
local ansicolors = require('ansicolors')

-- =============================================================================
-- Constants
-- =============================================================================

local FMCOS = {}

-- ISO 7816-4 Class bytes
FMCOS.CLA_ISO = 0x00
FMCOS.CLA_MAC = 0x04
FMCOS.CLA_PBOC = 0x80
FMCOS.CLA_PBOC_MAC = 0x84

-- ISO 7816-4 Instruction bytes
FMCOS.INS_VERIFY = 0x20
FMCOS.INS_EXTERNAL_AUTH = 0x82
FMCOS.INS_GET_CHALLENGE = 0x84
FMCOS.INS_INTERNAL_AUTH = 0x88
FMCOS.INS_SELECT = 0xA4
FMCOS.INS_READ_BINARY = 0xB0
FMCOS.INS_READ_RECORD = 0xB2
FMCOS.INS_GET_RESPONSE = 0xC0
FMCOS.INS_UPDATE_BINARY = 0xD6
FMCOS.INS_UPDATE_RECORD = 0xDC
FMCOS.INS_APPEND_RECORD = 0xE2

-- FMCOS Proprietary instructions
FMCOS.INS_ERASE_DF = 0x0E
FMCOS.INS_WRITE_KEY = 0xD4
FMCOS.INS_CREATE_FILE = 0xE0
FMCOS.INS_GET_BALANCE = 0x5C
FMCOS.INS_INIT_LOAD = 0x50
FMCOS.INS_CREDIT = 0x52
FMCOS.INS_INIT_PURCHASE = 0x54
FMCOS.INS_DEBIT = 0x54
FMCOS.INS_CHANGE_PIN = 0x5E
FMCOS.INS_PIN_UNBLOCK = 0x24
FMCOS.INS_CARD_BLOCK = 0x16
FMCOS.INS_APP_BLOCK = 0x1E
FMCOS.INS_APP_UNBLOCK = 0x18

-- Key type constants
FMCOS.KEY_TYPE_MASTER = 0x30
FMCOS.KEY_TYPE_MAINTAIN = 0x33
FMCOS.KEY_TYPE_APP_MASTER = 0x31
FMCOS.KEY_TYPE_APP_MAINTAIN = 0x34
FMCOS.KEY_TYPE_DES = 0x35
FMCOS.KEY_TYPE_PIN = 0x3A
FMCOS.KEY_TYPE_EXT_AUTH = 0x39
FMCOS.KEY_TYPE_LOAD_KEY = 0x3B
FMCOS.KEY_TYPE_TAC_KEY = 0x32
FMCOS.KEY_TYPE_DEBIT_KEY = 0x3F

-- File type constants for CREATE FILE
FMCOS.FILE_TYPE_DF = 0x38
FMCOS.FILE_TYPE_BINARY = 0x28
FMCOS.FILE_TYPE_FIXED_RECORD = 0x2A
FMCOS.FILE_TYPE_VARIABLE_RECORD = 0x2C
FMCOS.FILE_TYPE_CYCLIC_RECORD = 0x2E
FMCOS.FILE_TYPE_KEY_FILE = 0x3F
FMCOS.FILE_TYPE_WALLET = 0x2F

-- Status word descriptions
FMCOS.STATUS_WORDS = {
    [0x9000] = "Success",
    [0x6281] = "Part of data may be corrupted",
    [0x6283] = "Selected file invalidated",
    [0x6300] = "Verification failed (no retries)",
    [0x6581] = "Memory failure",
    [0x6700] = "Wrong length",
    [0x6882] = "Secure messaging not supported",
    [0x6982] = "Security status not satisfied",
    [0x6983] = "Authentication method blocked",
    [0x6984] = "Referenced data not usable",
    [0x6985] = "Conditions not satisfied",
    [0x6986] = "Command not allowed (no EF)",
    [0x6A80] = "Incorrect data field",
    [0x6A81] = "Function not supported",
    [0x6A82] = "File not found",
    [0x6A83] = "Record not found",
    [0x6A84] = "Not enough memory",
    [0x6A86] = "Incorrect P1-P2",
    [0x6A88] = "Key not found",
    [0x6B00] = "Wrong P1-P2",
    [0x6D00] = "INS not supported",
    [0x6E00] = "CLA not supported",
    [0x6F00] = "Unknown error",
    [0x9302] = "MAC error",
    [0x9303] = "Application locked",
    [0x9401] = "Insufficient balance",
    [0x9403] = "Key not found",
    [0x9406] = "MAC not available",
}

-- Module state
local _debug = false
local _card_info = nil

-- =============================================================================
-- Logging Functions
-- =============================================================================

local function log(msg)
    print(ansicolors.cyan .. '[=] ' .. ansicolors.reset .. msg)
end

local function log_success(msg)
    print(ansicolors.green .. '[+] ' .. ansicolors.reset .. msg)
end

local function log_error(msg)
    print(ansicolors.red .. '[!] ' .. ansicolors.reset .. msg)
end

local function log_warn(msg)
    print(ansicolors.yellow .. '[*] ' .. ansicolors.reset .. msg)
end

local function log_debug(msg)
    if _debug then
        print(ansicolors.white .. '[D] ' .. ansicolors.reset .. msg)
    end
end

FMCOS.log = log
FMCOS.log_success = log_success
FMCOS.log_error = log_error
FMCOS.log_warn = log_warn
FMCOS.log_debug = log_debug

-- =============================================================================
-- Utility Functions
-- =============================================================================

--- Set debug mode
function FMCOS.set_debug(enabled)
    _debug = enabled
end

--- Convert hex string to bytes display
function FMCOS.hex_to_display(hex)
    if not hex or #hex == 0 then return "" end
    local bytes = {}
    for i = 1, #hex, 2 do
        table.insert(bytes, hex:sub(i, i + 1):upper())
    end
    return table.concat(bytes, ' ')
end

--- Get status word description
function FMCOS.get_sw_description(sw1, sw2)
    local sw = sw1 * 256 + sw2

    -- Check exact match
    if FMCOS.STATUS_WORDS[sw] then
        return FMCOS.STATUS_WORDS[sw]
    end

    -- Check retry counter (63CX)
    if sw1 == 0x63 and (sw2 >= 0xC0 and sw2 <= 0xCF) then
        return string.format("Verification failed (%d retries left)", sw2 - 0xC0)
    end

    -- Check 61XX (more data)
    if sw1 == 0x61 then
        return string.format("More data available (%d bytes)", sw2)
    end

    return string.format("Unknown (SW=%02X%02X)", sw1, sw2)
end

--- Check if SW indicates success
function FMCOS.check_sw(sw1, sw2)
    return sw1 == 0x90 and sw2 == 0x00
end

--- Parse and display raw response in detailed format (like PM3 ATS parser)
function FMCOS.parse_response_debug(raw_hex, show_data)
    if not raw_hex or #raw_hex < 8 then
        log_debug("[!] Response too short to parse")
        return
    end

    -- Response format: [DATA...] [SW1] [SW2] [CRC1] [CRC2]
    local crc_hex = raw_hex:sub(-4)
    local data_sw = raw_hex:sub(1, -5)
    local sw_hex = data_sw:sub(-4)
    local data_hex = ""
    if #data_sw > 4 then
        data_hex = data_sw:sub(1, -5)
    end

    local sw1 = tonumber(sw_hex:sub(1, 2), 16)
    local sw2 = tonumber(sw_hex:sub(3, 4), 16)

    -- Header with raw hex
    local display_hex = FMCOS.hex_to_display(data_sw) .. " [ " .. FMCOS.hex_to_display(crc_hex) .. " ]"
    log_debug("<< " .. display_hex)

    -- Separator
    log_debug("   " .. string.rep("-", 60))

    -- Data field
    if #data_hex > 0 then
        local data_len = #data_hex / 2
        log_debug(string.format("   DATA  %d bytes", data_len))

        -- Show data in rows of 16 bytes with ASCII
        if show_data then
            for i = 1, #data_hex, 32 do
                local row = data_hex:sub(i, math.min(i + 31, #data_hex))
                local offset = (i - 1) / 2

                -- Build ASCII representation
                local ascii = ""
                for j = 1, #row, 2 do
                    local byte = tonumber(row:sub(j, j + 1), 16)
                    if byte >= 0x20 and byte < 0x7F then
                        ascii = ascii .. string.char(byte)
                    else
                        ascii = ascii .. "."
                    end
                end

                -- Pad hex display to 48 chars (16 bytes * 3 chars each)
                local hex_display = FMCOS.hex_to_display(row)
                local padding = 48 - #hex_display
                if padding > 0 then
                    hex_display = hex_display .. string.rep(" ", padding)
                end

                log_debug(string.format("   %04X: %s |%s|", offset, hex_display, ascii))
            end
        end
    end

    -- SW field
    log_debug(string.format("   SW    %s (%s)", sw_hex, FMCOS.get_sw_description(sw1, sw2)))

    -- CRC field
    log_debug(string.format("   CRC   %s", crc_hex))
end

-- =============================================================================
-- Simple DES Implementation (ECB mode)
-- =============================================================================

-- DES permutation tables
local PC1 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4 }

local PC2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 }

local IP = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 }

local IP_INV = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 }

local E = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 }

local P = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 }

local S = {
    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
}

local SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }

--- Permute bits according to table
local function permute(input, table_p, in_bits)
    local output = 0
    local out_bits = #table_p
    for i = 1, out_bits do
        local bit_pos = table_p[i]
        local bit_val = (input >> (in_bits - bit_pos)) & 1
        output = output | (bit_val << (out_bits - i))
    end
    return output
end

--- Left rotate 28-bit value
local function left_rotate_28(val, n)
    return ((val << n) | (val >> (28 - n))) & 0x0FFFFFFF
end

--- Generate 16 round keys from 8-byte key
local function generate_keys(key_bytes)
    -- Convert key bytes to 64-bit integer
    local key64 = 0
    for i = 1, 8 do
        key64 = (key64 << 8) | key_bytes:byte(i)
    end

    -- Apply PC1 (64 -> 56 bits)
    local key56 = permute(key64, PC1, 64)

    -- Split into C and D (28 bits each)
    local C = (key56 >> 28) & 0x0FFFFFFF
    local D = key56 & 0x0FFFFFFF

    local round_keys = {}
    for round = 1, 16 do
        -- Left rotate C and D
        C = left_rotate_28(C, SHIFTS[round])
        D = left_rotate_28(D, SHIFTS[round])

        -- Combine and apply PC2 (56 -> 48 bits)
        local CD = (C << 28) | D
        round_keys[round] = permute(CD, PC2, 56)
    end

    return round_keys
end

--- DES F function
local function f_function(R, K)
    -- Expand R from 32 to 48 bits
    local expanded = permute(R, E, 32)

    -- XOR with round key
    local xored = expanded ~ K

    -- S-box substitution (48 -> 32 bits)
    local sbox_out = 0
    for i = 1, 8 do
        local block = (xored >> (42 - (i - 1) * 6)) & 0x3F
        local row = ((block & 0x20) >> 4) | (block & 0x01)
        local col = (block >> 1) & 0x0F
        local s_val = S[i][row * 16 + col + 1]
        sbox_out = (sbox_out << 4) | s_val
    end

    -- Apply P permutation
    return permute(sbox_out, P, 32)
end

--- Encrypt 8-byte block with DES ECB
function FMCOS.des_encrypt(key_bytes, block_bytes)
    if #key_bytes ~= 8 then
        return nil, "Key must be 8 bytes"
    end
    if #block_bytes ~= 8 then
        return nil, "Block must be 8 bytes"
    end

    -- Convert block to 64-bit integer
    local block64 = 0
    for i = 1, 8 do
        block64 = (block64 << 8) | block_bytes:byte(i)
    end

    -- Generate round keys
    local round_keys = generate_keys(key_bytes)

    -- Initial permutation
    local permuted = permute(block64, IP, 64)

    -- Split into L and R
    local L = (permuted >> 32) & 0xFFFFFFFF
    local R = permuted & 0xFFFFFFFF

    -- 16 rounds
    for round = 1, 16 do
        local new_R = L ~ f_function(R, round_keys[round])
        L = R
        R = new_R
    end

    -- Combine R and L (swapped) and apply final permutation
    local combined = (R << 32) | L
    local result = permute(combined, IP_INV, 64)

    -- Convert back to bytes
    local result_bytes = ""
    for i = 7, 0, -1 do
        result_bytes = result_bytes .. string.char((result >> (i * 8)) & 0xFF)
    end

    return result_bytes
end

--- Decrypt 8-byte block with DES ECB
function FMCOS.des_decrypt(key_bytes, block_bytes)
    if #key_bytes ~= 8 then return nil, "Key must be 8 bytes" end
    if #block_bytes ~= 8 then return nil, "Block must be 8 bytes" end

    local block64 = 0
    for i = 1, 8 do block64 = (block64 << 8) | block_bytes:byte(i) end

    local round_keys = generate_keys(key_bytes)
    local permuted = permute(block64, IP, 64)
    local L = (permuted >> 32) & 0xFFFFFFFF
    local R = permuted & 0xFFFFFFFF

    for round = 16, 1, -1 do
        local new_R = L ~ f_function(R, round_keys[round])
        L = R
        R = new_R
    end

    local combined = (R << 32) | L
    local result = permute(combined, IP_INV, 64)
    local result_bytes = ""
    for i = 7, 0, -1 do
        result_bytes = result_bytes .. string.char((result >> (i * 8)) & 0xFF)
    end
    return result_bytes
end

--- 3DES Encrypt (2-key Key1=Key3)
function FMCOS.des3_encrypt(key_bytes, block_bytes)
    if #key_bytes ~= 16 then return nil, "Key must be 16 bytes" end
    local k1 = key_bytes:sub(1, 8)
    local k2 = key_bytes:sub(9, 16)

    -- E(K1, D(K2, E(K1, M)))
    local temp = FMCOS.des_encrypt(k1, block_bytes)
    temp = FMCOS.des_decrypt(k2, temp) -- Wait, des_decrypt needed!
    temp = FMCOS.des_encrypt(k1, temp)
    return temp
end

--- Calculate MAC (ISO/IEC 9797-1 Algo 3 / FMCOS style)
-- Supported Key: 8 bytes (DES MAC) or 16 bytes (3DES MAC)
function FMCOS.calculate_mac(data, key, iv)
    iv = iv or string.rep("\0", 8)

    -- 1. Padding
    local pad_len = 8 - (#data % 8)
    local padded = data .. string.char(0x80) .. string.rep("\0", pad_len - 1)

    -- 2. MAC Loop
    local block_count = #padded / 8
    local current_iv = iv

    -- Function to XOR strings
    local function xor_str(a, b)
        local res = {}
        for i = 1, #a do table.insert(res, string.char(a:byte(i) ~ b:byte(i))) end
        return table.concat(res)
    end

    for i = 0, block_count - 1 do
        local block = padded:sub(i * 8 + 1, i * 8 + 8)
        local xored = xor_str(current_iv, block)

        -- Encrypt
        if #key == 8 then
            current_iv = FMCOS.des_encrypt(key, xored)
        else
            -- 3DES MAC: Inner blocks use Single DES with K1?
            -- Python: val = DESECB.encrypt(xor_data) using K1 only!
            -- Standard Retail MAC usually uses Single DES for blocks, and 3DES for Final?
            -- Python fmcos_3des_mac lines 324:
            -- key_l = key[:8]... val = fmcos_des_mac(buf, key_l... ret_cnt=8)
            -- val = DESECB_R.decrypt(val)
            -- val = DESECB_L.encrypt(val)

            -- So ALL blocks encrypted with K1. Final result Decrypt(K2), Encrypt(K1).
            current_iv = FMCOS.des_encrypt(key:sub(1, 8), xored)
        end
    end

    -- Final 3DES step if 16 byte key
    if #key == 16 then
        local k1 = key:sub(1, 8)
        local k2 = key:sub(9, 16)
        current_iv = FMCOS.des_decrypt(k2, current_iv)
        current_iv = FMCOS.des_encrypt(k1, current_iv)
    end

    return current_iv:sub(1, 4) -- Default 4 byte MAC
end

-- =============================================================================
-- Core APDU Functions
-- =============================================================================

--- Connect to card
function FMCOS.connect(no_rats)
    log("Connecting to card...")
    local card_info, err = lib14a.read(true, no_rats or false)
    if err then
        log_error("Connection failed: " .. err)
        return nil, err
    end
    _card_info = card_info
    log_success("Connected: UID=" .. card_info.uid)
    log("ATQA=" .. card_info.atqa .. ", SAK=" .. string.format("%02X", card_info.sak))
    return card_info, nil
end

--- Disconnect from card
function FMCOS.disconnect()
    log_debug("Disconnecting...")
    lib14a.disconnect()
    _card_info = nil
end

--- Get card info
function FMCOS.get_card_info()
    return _card_info
end

--- Send raw APDU with proper session control
-- @param apdu_hex APDU as hex string
-- @param keep_field Keep RF field on (default: true)
-- @return response_hex, sw1, sw2, error
function FMCOS.send_apdu_raw(apdu_hex, keep_field)
    if keep_field == nil then keep_field = true end

    log_debug(">> " .. FMCOS.hex_to_display(apdu_hex))

    -- Build flags - use ISO14A_APDU for ISO7816 APDUs (not ISO14A_RAW!)
    local flags = lib14a.ISO14A_COMMAND.ISO14A_APDU

    if keep_field then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
    end

    -- Send command
    local command = Command:newMIX {
        cmd = cmds.CMD_HF_ISO14443A_READER,
        arg1 = flags,
        arg2 = #apdu_hex / 2,
        data = apdu_hex
    }

    local result, err = command:sendMIX(false)
    if err then
        log_error("APDU error: " .. tostring(err))
        return nil, nil, nil, err
    end

    if not result then
        log_error("No result from sendMIX")
        return nil, nil, nil, "No result"
    end

    -- Parse response
    local cmd_response = Command.parse(result)
    local len = tonumber(cmd_response.arg1) * 2

    if len < 8 then
        log_debug("<< (no response)")
        return nil, nil, nil, "No response from card"
    end

    -- Get raw response data
    local raw_data = string.sub(tostring(cmd_response.data), 1, len)

    -- Debug: show parsed response in detailed format
    FMCOS.parse_response_debug(raw_data, true)

    -- PM3 includes CRC in response - strip last 4 hex chars (2 bytes CRC)
    -- Response format: [DATA] [SW1 SW2] [CRC16]
    local data = raw_data:sub(1, -5)

    -- Extract SW1 SW2 (last 4 hex chars after stripping CRC)
    local sw_hex = data:sub(-4)
    local sw1 = tonumber(sw_hex:sub(1, 2), 16)
    local sw2 = tonumber(sw_hex:sub(3, 4), 16)

    -- Response data (without SW)
    local resp_data = ""
    if #data > 4 then
        resp_data = data:sub(1, -5)
    end

    return resp_data, sw1, sw2, nil
end

--- Build APDU hex string from components
function FMCOS.build_apdu(cla, ins, p1, p2, data_hex, le)
    local apdu = string.format("%02X%02X%02X%02X", cla, ins, p1, p2)

    if data_hex and #data_hex > 0 then
        local lc = #data_hex / 2
        apdu = apdu .. string.format("%02X", lc) .. data_hex
    end

    if le then
        apdu = apdu .. string.format("%02X", le)
    end

    return apdu
end

--- Send APDU command
-- @param cla Class byte
-- @param ins Instruction byte
-- @param p1 Parameter 1
-- @param p2 Parameter 2
-- @param data_hex Data as hex string (optional)
-- @param le Expected response length (optional)
-- @param keep_field Keep RF field on (default: true)
-- @return response_hex, sw1, sw2, error
function FMCOS.send_apdu(cla, ins, p1, p2, data_hex, le, keep_field)
    local apdu = FMCOS.build_apdu(cla, ins, p1, p2, data_hex, le)
    return FMCOS.send_apdu_raw(apdu, keep_field)
end

-- =============================================================================
-- High-Level Commands
-- =============================================================================

--- Select file by FID
function FMCOS.select_file(fid, keep_field, silent)
    local fid_hex = ""
    if type(fid) == "number" then
        fid_hex = string.format("%04X", fid)
    else
        fid_hex = fid -- Assume hex string
    end

    -- Check if it's a path (length > 4)
    if #fid_hex > 4 then
        -- Card rejected hardware path select (P1=08), so we do iterative select
        if not silent then
            log("SELECT PATH: " .. fid_hex)
        end

        local resp, sw1, sw2, err
        -- Iterate every 4 chars (2 bytes)
        for i = 1, #fid_hex, 4 do
            local part_fid = fid_hex:sub(i, i + 3)
            -- Recursive call for single FID select
            resp, sw1, sw2, err = FMCOS.select_file(part_fid, keep_field, true) -- internal silent

            if err or not FMCOS.check_sw(sw1, sw2) then
                if not silent then
                    log_error("Select failed at " .. part_fid .. ": " .. FMCOS.get_sw_description(sw1, sw2))
                end
                return nil, sw1, sw2, err
            end
        end
        if not silent then
            log_success("Path selected: " .. fid_hex)
        end
        return resp, sw1, sw2, nil
    end

    -- Standard Single FID Select (2 bytes)
    if not silent then
        log("SELECT FILE: " .. fid_hex)
    end

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_SELECT, 0x00, 0x00,
        fid_hex, 0x00, keep_field
    )

    if err then return nil, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        if not silent then
            log_success("File selected: " .. fid_hex)
        end
        return resp, sw1, sw2, nil
    else
        if not silent then
            log_error("Select failed: " .. FMCOS.get_sw_description(sw1, sw2))
        end
        return nil, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Select DF by name (AID)
function FMCOS.select_df(df_name_hex, keep_field)
    log("SELECT DF: " .. df_name_hex)

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_SELECT, 0x04, 0x00,
        df_name_hex, 0x00, keep_field
    )

    if err then return nil, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("DF selected")
        return resp, sw1, sw2, nil
    else
        log_error("Select DF failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return nil, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Read binary file
function FMCOS.read_binary(offset, length, sfi, keep_field, silent)
    local p1, p2
    if sfi then
        p1 = 0x80 | (sfi & 0x1F)
        p2 = offset & 0xFF
    else
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
    end

    if not silent then
        log(string.format("READ BINARY: offset=%d, len=%d", offset, length))
    end

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_READ_BINARY, p1, p2,
        nil, length, keep_field
    )

    if err then return nil, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        if not silent then
            log_success("Read " .. (#resp / 2) .. " bytes")
        end
        return resp, sw1, sw2, nil
    else
        if not silent then
            log_error("Read failed: " .. FMCOS.get_sw_description(sw1, sw2))
        end
        return nil, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Update binary file
function FMCOS.update_binary(offset, data_hex, sfi, keep_field)
    local p1, p2
    if sfi then
        p1 = 0x80 | (sfi & 0x1F)
        p2 = offset & 0xFF
    else
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
    end

    log(string.format("UPDATE BINARY: offset=%d, %d bytes", offset, #data_hex / 2))

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_UPDATE_BINARY, p1, p2,
        data_hex, nil, keep_field
    )

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("Write successful")
        return true, sw1, sw2, nil
    else
        log_error("Write failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Read record
function FMCOS.read_record(record_num, sfi, length, keep_field, silent)
    local p2
    if sfi then
        p2 = ((sfi & 0x1F) << 3) | 0x04
    else
        p2 = 0x04
    end

    if not silent then
        log(string.format("READ RECORD: #%d", record_num))
    end

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_READ_RECORD, record_num, p2,
        nil, length or 0, keep_field
    )

    if err then return nil, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        if not silent then
            log_success("Read record: " .. (#resp / 2) .. " bytes")
        end
        return resp, sw1, sw2, nil
    else
        if not silent then
            log_error("Read record failed: " .. FMCOS.get_sw_description(sw1, sw2))
        end
        return nil, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Update record
function FMCOS.update_record(record_num, data_hex, sfi, keep_field)
    local p2
    if sfi then
        p2 = ((sfi & 0x1F) << 3) | 0x04
    else
        p2 = 0x04
    end

    log(string.format("UPDATE RECORD: #%d, %d bytes", record_num, #data_hex / 2))

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_UPDATE_RECORD, record_num, p2,
        data_hex, nil, keep_field
    )

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("Record updated")
        return true, sw1, sw2, nil
    else
        log_error("Update record failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Get random challenge
function FMCOS.get_challenge(length, keep_field)
    length = length or 8
    if length ~= 4 and length ~= 8 then
        length = 8
    end

    log("GET CHALLENGE: " .. length .. " bytes")

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_GET_CHALLENGE, 0x00, 0x00,
        nil, length, keep_field
    )

    if err then return nil, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("Challenge: " .. FMCOS.hex_to_display(resp))
        return resp, sw1, sw2, nil
    else
        log_error("Get challenge failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return nil, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- External authenticate
function FMCOS.external_auth(key_id, cryptogram_hex, keep_field)
    log("EXTERNAL AUTH: Key=" .. string.format("%02X", key_id))

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_EXTERNAL_AUTH, 0x00, key_id,
        cryptogram_hex, nil, keep_field
    )

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("External authentication successful")
        return true, sw1, sw2, nil
    else
        log_error("External auth failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Fast external authenticate (get challenge + encrypt + auth)
function FMCOS.fast_ext_auth(key_id, key_hex, keep_field)
    -- Get 4-byte challenge
    local challenge, sw1, sw2, err = FMCOS.get_challenge(4, true)
    if not challenge then
        return false, sw1, sw2, err
    end

    -- Pad to 8 bytes
    local padded_hex = challenge .. "00000000"

    -- Convert key and data to bytes
    local key_bytes = ""
    for i = 1, #key_hex, 2 do
        key_bytes = key_bytes .. string.char(tonumber(key_hex:sub(i, i + 1), 16))
    end

    local data_bytes = ""
    for i = 1, #padded_hex, 2 do
        data_bytes = data_bytes .. string.char(tonumber(padded_hex:sub(i, i + 1), 16))
    end

    -- DES encrypt
    local encrypted, des_err = FMCOS.des_encrypt(key_bytes, data_bytes)
    if not encrypted then
        log_error("DES encryption failed: " .. tostring(des_err))
        return false, nil, nil, des_err
    end

    -- Convert to hex
    local encrypted_hex = ""
    for i = 1, #encrypted do
        encrypted_hex = encrypted_hex .. string.format("%02X", encrypted:byte(i))
    end

    -- External auth
    return FMCOS.external_auth(key_id, encrypted_hex, keep_field)
end

--- Internal authenticate / DES operation
function FMCOS.internal_auth(key_id, data_hex, operation, keep_field)
    operation = operation or 0x00 -- 0=encrypt, 1=decrypt, 2=MAC

    log("INTERNAL AUTH: Key=" .. string.format("%02X", key_id))

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_INTERNAL_AUTH, operation, key_id,
        data_hex, 0x00, keep_field
    )

    if err then return nil, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("Result: " .. FMCOS.hex_to_display(resp))
        return resp, sw1, sw2, nil
    else
        log_error("Internal auth failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return nil, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Verify PIN
function FMCOS.verify_pin(key_id, pin_hex, keep_field)
    log("VERIFY PIN: Key=" .. string.format("%02X", key_id))

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_VERIFY, 0x00, key_id,
        pin_hex, nil, keep_field
    )

    if err then return -1, false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("PIN verified")
        return -1, true, sw1, sw2, nil
    else
        local retries = 0
        if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0 then
            retries = sw2 & 0x0F
            log_error(string.format("PIN incorrect, %d retries left", retries))
        else
            log_error("PIN verify failed: " .. FMCOS.get_sw_description(sw1, sw2))
        end
        return retries, false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Get e-purse/e-passbook balance
function FMCOS.get_balance(app_type, keep_field)
    app_type = app_type or 0x02 -- 0x01=passbook, 0x02=purse

    log("GET BALANCE")

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_GET_BALANCE, 0x00, app_type,
        nil, 0x04, keep_field
    )

    if err then return nil, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) and #resp >= 8 then
        -- Balance is 4 bytes big-endian
        local balance = 0
        for i = 1, 8, 2 do
            balance = (balance << 8) | tonumber(resp:sub(i, i + 1), 16)
        end
        log_success(string.format("Balance: %d (¥%.2f)", balance, balance / 100))
        return balance, sw1, sw2, nil
    else
        log_error("Get balance failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return nil, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Create file
function FMCOS.create_file(file_type, fid, size, options, keep_field)
    options = options or {}

    log(string.format("CREATE FILE: FID=%04X, Type=%02X, Size=%d", fid, file_type, size))

    local data = ""

    -- Build file descriptor based on type
    local p1 = 0x00
    local p2 = 0x00

    -- Build file descriptor based on type
    if file_type == FMCOS.FILE_TYPE_DF then
        -- DF: Type(1) + SFI(1) + FID(2) + SpaceSize(2) + DFName(1-16)
        data = string.format("%02X%02X%04X%04X",
            file_type,
            options.sfi or 0x00,
            fid,
            size
        ) .. (options.df_name or "")
    elseif file_type == FMCOS.FILE_TYPE_BINARY then
        -- Binary EF: Type(1) + Size(2) + Perms(variable) from options
        -- P1 P2 must be FID
        p1 = (fid >> 8) & 0xFF
        p2 = fid & 0xFF

        local perm = options.perm or "FFFFFFFFFF" -- Default perms: Auth required, Plaintext OK

        data = string.format("%02X%04X", file_type, size) .. perm
    elseif file_type == FMCOS.FILE_TYPE_FIXED_RECORD or
        file_type == FMCOS.FILE_TYPE_VARIABLE_RECORD or
        file_type == FMCOS.FILE_TYPE_CYCLIC_RECORD then
        -- Record EF: Type(1) + SFI(1) + Count(1) + Len(1) + Perms
        -- P1 P2 = FID
        p1 = (fid >> 8) & 0xFF
        p2 = fid & 0xFF

        local perm = options.perm or "FFFFFFFFFF"
        local sfi = options.sfi or 0x01 -- Default SFI to 1 if not specified (0 did not work before?)
        local rec_len = size
        local rec_count = options.record_count or 10

        data = string.format("%02X%02X%02X%02X", file_type, sfi, rec_count, rec_len) .. perm
    elseif file_type == FMCOS.FILE_TYPE_KEY_FILE then
        -- Key file: Type(1) + ProtType(1) + SFI(1) + FID(2) + KeyNum(1)
        data = string.format("%02X%02X%02X%04X%02X",
            file_type,
            options.prot_type or 0x00,
            options.sfi or 0x00,
            fid,
            options.key_count or size
        )
    else
        return false, nil, nil, "Unknown file type"
    end

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_CREATE_FILE, p1, p2,
        data, nil, keep_field
    )

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("File created")
        return true, sw1, sw2, nil
    else
        log_error("Create file failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Write key
function FMCOS.write_key(key_id, key_data_hex, add_mode, key_type, keep_field)
    local p1 = add_mode and 0x01 or (key_type or 0x00)

    log("WRITE KEY: ID=" .. string.format("%02X", key_id))

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_WRITE_KEY, p1, key_id,
        key_data_hex, nil, keep_field
    )

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("Key written")
        return true, sw1, sw2, nil
    else
        log_error("Write key failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Erase DF
--- Erase DF
function FMCOS.erase_df(keep_field)
    log_warn("ERASE DF (DANGEROUS!)")

    -- FMCOS requires Lc=00 for ERASE DF (80 0E 00 00 00)
    -- build_apdu skips Lc if data is empty, so we build manually
    local apdu = string.format("%02X%02X000000", FMCOS.CLA_PBOC, FMCOS.INS_ERASE_DF)

    local resp, sw1, sw2, err = FMCOS.send_apdu_raw(apdu, keep_field)

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("DF erased")
        return true, sw1, sw2, nil
    else
        log_error("Erase DF failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Create DF (Directory File / Application)
-- FMCOS CREATE FILE format for DF:
-- APDU: 80 E0 [FID_H] [FID_L] Lc [Type] [Space] [Reserved] [Perm 5 bytes] [DF Name...]
-- Example: 80 E0 3F 01 0D 38 08 00 F0 F0 95 FF FF 11 22 33 44 55
-- @param fid File identifier (e.g., 0x3F01)
-- @param space Space allocation code (08 = 2048 bytes)
-- @param df_name_hex DF name in hex (1-16 bytes)
-- @param perm_hex Permissions (5 bytes: read, write, lock, read_ac, write_ac)
-- @param keep_field Keep RF field on
function FMCOS.create_df(fid, space, df_name_hex, perm_hex, keep_field)
    perm_hex = perm_hex or "F0F095FFFF" -- Default permissions
    df_name_hex = df_name_hex or ""

    log(string.format("CREATE DF: FID=%04X, Space=%02X, Name=%s", fid, space, df_name_hex))

    -- Build data: Type(1) + Space(1) + Reserved(1) + Perm(5) + DFName(n)
    -- Type = 0x38 for DF
    local data = string.format("%02X%02X00", 0x38, space) .. perm_hex .. df_name_hex

    -- P1P2 = FID
    local p1 = (fid >> 8) & 0xFF
    local p2 = fid & 0xFF

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_CREATE_FILE, p1, p2,
        data, nil, keep_field
    )

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success(string.format("DF created: %04X", fid))
        return true, sw1, sw2, nil
    else
        log_error("Create DF failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

--- Create Key File
-- FMCOS CREATE FILE format for Key File:
-- APDU: 80 E0 00 00 Lc [Type] [KeySlots] [Property] [Perm 4 bytes]
-- Example: 80 E0 00 00 07 3F 01 8F 95 F0 FF FF
-- @param fid File identifier (encoded in data, not P1P2!)
-- @param key_slots Number of key slots
-- @param prop_hex Property and permissions hex (e.g., "8F95F0FFFF")
-- @param keep_field Keep RF field on
function FMCOS.create_key_file(fid, key_slots, prop_hex, keep_field)
    prop_hex = prop_hex or "8F95F0FFFF" -- Default property + permissions

    log(string.format("CREATE KEY FILE: FID=%04X, Slots=%d", fid, key_slots))

    -- Build data: Type(1) + KeySlots(1) + Property(1) + Perm(4)
    -- Type = 0x3F for Key File
    -- Note: FID seems to be encoded in property byte in FMCOS 2.0
    local data = string.format("%02X%02X", 0x3F, key_slots) .. prop_hex

    -- P1P2 = 0000 for key file
    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_CREATE_FILE, 0x00, 0x00,
        data, nil, keep_field
    )

    if err then return false, sw1, sw2, err end

    if FMCOS.check_sw(sw1, sw2) then
        log_success("Key file created")
        return true, sw1, sw2, nil
    else
        log_error("Create key file failed: " .. FMCOS.get_sw_description(sw1, sw2))
        return false, sw1, sw2, FMCOS.get_sw_description(sw1, sw2)
    end
end

-- =============================================================================
-- New Ported Functions (from fmcos.py)
-- =============================================================================

--- Calculate Packet MAC (Header + Data + Padding)
function FMCOS.packet_mac(cla, ins, p1, p2, data, iv, key)
    local header = string.char(cla, ins, p1, p2)
    local lc = 4
    if data and #data > 0 then
        lc = #data + 4
        header = header .. string.char(lc & 0xFF) .. data
    else
        header = header .. string.char(0x04)
    end
    -- Calculate MAC uses ISO padding internally
    return FMCOS.calculate_mac(header, key, iv)
end

--- Encrypt Data (ISO7816 Padding + ECB)
function FMCOS.encrypt_data(data, key)
    local pad_len = 8 - (#data % 8)
    local padded = data .. string.char(0x80) .. string.rep("\0", pad_len - 1)

    local out = ""
    for i = 0, (#padded / 8) - 1 do
        local block = padded:sub(i * 8 + 1, i * 8 + 8)
        if #key == 8 then
            out = out .. FMCOS.des_encrypt(key, block)
        else
            out = out .. FMCOS.des3_encrypt(key, block)
        end
    end
    return out
end

--- Internal Authenticate
function FMCOS.internal_authenticate(p1, p2, data, keep_field)
    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_ISO, FMCOS.INS_INTERNAL_AUTH, p1, p2,
        data, nil, keep_field
    )
    if err then return nil, sw1, sw2, err end
    return resp, sw1, sw2, nil
end

--- Append Record
function FMCOS.append_record(data, sfi, keep_field)
    local p2 = 0
    if sfi then
        p2 = ((sfi & 0x1F) << 3) | 4 -- SFI addressing
    end

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_APPEND_RECORD, 0x00, p2,
        data, nil, keep_field
    )
    return FMCOS.check_sw(sw1, sw2), sw1, sw2, err
end

--- Modify PIN (User Change)
function FMCOS.modify_pin(kid, old_pin_hex, new_pin_hex, keep_field)
    local data = utils.hex_to_bytes(old_pin_hex) .. string.char(0xFF) .. utils.hex_to_bytes(new_pin_hex)
    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_CHANGE_PIN, 0x01, kid,
        data, nil, keep_field
    )
    return FMCOS.check_sw(sw1, sw2), sw1, sw2, err
end

--- Reload PIN (Admin Change)
function FMCOS.reload_pin(kid, new_pin_hex, change_pin_key_hex, keep_field)
    local c_key = utils.hex_to_bytes(change_pin_key_hex)
    local pin_bytes = utils.hex_to_bytes(new_pin_hex)

    -- Calculate MAC Key = XOR(K1, K2)
    local k1 = c_key:sub(1, 8)
    local k2 = c_key:sub(9, 16)
    local mac_key_tbl = {}
    for i = 1, 8 do table.insert(mac_key_tbl, string.char(k1:byte(i) ~ k2:byte(i))) end
    local mac_key = table.concat(mac_key_tbl)

    local mac = FMCOS.calculate_mac(pin_bytes, mac_key)
    local data = pin_bytes .. mac

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC, FMCOS.INS_CHANGE_PIN, 0x00, kid,
        data, nil, keep_field
    )
    return FMCOS.check_sw(sw1, sw2), sw1, sw2, err
end

--- Unlock PIN
function FMCOS.unlock_pin(kid, new_pin_hex, unlock_pin_key_hex, keep_field)
    local u_key = utils.hex_to_bytes(unlock_pin_key_hex)
    local pin_bytes = utils.hex_to_bytes(new_pin_hex)

    -- Data = Len + Pin
    local plain = string.char(#pin_bytes) .. pin_bytes
    local enc_data = FMCOS.encrypt_data(plain, u_key)

    -- Challenge
    local chlg = FMCOS.get_challenge(8, true)
    if not chlg then return false, 0, 0, "Get Challenge failed" end

    -- Packet MAC
    local mac = FMCOS.packet_mac(FMCOS.CLA_PBOC_MAC, FMCOS.INS_PIN_UNBLOCK, kid, 0x00, enc_data, chlg, u_key)
    local data = enc_data .. mac

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC_MAC, FMCOS.INS_PIN_UNBLOCK, kid, 0x00,
        data, nil, keep_field
    )
    return FMCOS.check_sw(sw1, sw2), sw1, sw2, err
end

--- Card Block
function FMCOS.card_block(line_key_hex, keep_field)
    local l_key = utils.hex_to_bytes(line_key_hex)
    local chlg = FMCOS.get_challenge(8, true)
    if not chlg then return false, 0, 0, "Get Challenge failed" end

    local mac = FMCOS.packet_mac(FMCOS.CLA_PBOC_MAC, FMCOS.INS_CARD_BLOCK, 0x00, 0x00, nil, chlg, l_key)

    local resp, sw1, sw2, err = FMCOS.send_apdu(
        FMCOS.CLA_PBOC_MAC, FMCOS.INS_CARD_BLOCK, 0x00, 0x00,
        mac, nil, keep_field
    )
    return FMCOS.check_sw(sw1, sw2), sw1, sw2, err
end

return FMCOS
