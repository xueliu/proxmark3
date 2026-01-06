--[[
    FMCOS 2.0 Smart Card CLI for Proxmark3 (Lua)

    Subcommand-style CLI for FMCOS card operations.

    Usage:
        script run hf_fmcos <command> [options]

    Commands:
        select, read_binary, update_binary, read_record, update_record,
        ext_auth, verify, challenge, create_file, write_key, erase_df,
        balance, run

    Common Options:
        -s <fid>    Select file first
        -a <kid>    Key ID for external authentication
        -k <key>    Key value (16 hex chars)
        -d          Debug mode

    Author: Xue Liu <liuxuenetmail@gmail.com>
    License: GPL-3.0
--]]

local getopt = require('getopt')
local ansicolors = require('ansicolors')
local fmcos = require('fmcos')

copyright = '(c) 2026 Xue Liu'
author = 'Xue Liu <liuxuenetmail@gmail.com>'
version = 'v2.0.0'
desc = [[
FMCOS 2.0 Smart Card CLI for Proxmark3.

Subcommand-style interface following FMCOS command specification.
Each command follows the pattern: select (-s) -> auth (-a -k) -> execute
]]

usage = [[
script run hf_fmcos <command> [options]
]]

-- =============================================================================
-- Utility Functions
-- =============================================================================

local function parse_hex(s)
    if not s then return nil end
    s = s:gsub('%s', ''):upper()
    return s
end

local function parse_number(s, base)
    if not s then return nil end
    base = base or 10
    if s:sub(1, 2):lower() == '0x' then
        return tonumber(s:sub(3), 16)
    end
    return tonumber(s, base)
end

local function split(str, sep)
    local result = {}
    for part in str:gmatch('([^' .. sep .. ']+)') do
        table.insert(result, part)
    end
    return result
end

local function ascii_to_hex(s)
    if not s then return nil end
    local hex = ""
    for i = 1, #s do
        hex = hex .. string.format("%02X", string.byte(s, i))
    end
    return hex
end

local function strip_quotes(s)
    if not s then return nil end
    -- Remove surrounding quotes (single or double)
    if (s:sub(1, 1) == '"' and s:sub(-1) == '"') or
        (s:sub(1, 1) == "'" and s:sub(-1) == "'") then
        return s:sub(2, -2)
    end
    return s
end

-- =============================================================================
-- Common Option Parsing
-- =============================================================================

local function parse_common_options(args, start_idx)
    local opts = {
        select_fid = nil,
        auth_kid = nil,
        auth_key = nil,
        debug = false,
        positional = {},
        named = {}
    }

    local i = start_idx or 2
    while i <= #args do
        local arg = args[i]

        if arg == '-s' and args[i + 1] then
            opts.select_fid = parse_number(args[i + 1], 16)
            i = i + 2
        elseif arg == '-a' and args[i + 1] then
            opts.auth_kid = parse_number(args[i + 1], 16)
            i = i + 2
        elseif arg == '-k' and args[i + 1] then
            opts.auth_key = parse_hex(args[i + 1])
            i = i + 2
        elseif arg == '-d' then
            opts.debug = true
            i = i + 1
        elseif arg == '-f' and args[i + 1] then
            opts.named.file = args[i + 1]
            i = i + 2
        elseif arg == '-n' and args[i + 1] then
            opts.named.name = parse_hex(args[i + 1])
            i = i + 2
        elseif arg == '--type' and args[i + 1] then
            opts.named.type = strip_quotes(args[i + 1]):lower()
            i = i + 2
        elseif arg == '--perm' and args[i + 1] then
            opts.named.perm = parse_hex(args[i + 1])
            i = i + 2
        elseif arg == '--sfi' and args[i + 1] then
            opts.named.sfi = parse_number(args[i + 1], 16)
            i = i + 2
        elseif arg == '--space' and args[i + 1] then
            opts.named.space = parse_number(args[i + 1], 16)
            i = i + 2
        elseif arg == '--mode' and args[i + 1] then
            opts.named.mode = strip_quotes(args[i + 1]):lower()
            i = i + 2
        elseif arg == '--start' and args[i + 1] then
            opts.named.start = strip_quotes(args[i + 1])
            i = i + 2
        elseif arg == '--end' and args[i + 1] then
            opts.named['end'] = strip_quotes(args[i + 1])
            i = i + 2
        elseif arg == '--pin' and args[i + 1] then
            opts.named.pin = strip_quotes(args[i + 1])
            i = i + 2
        elseif arg == '--key' and args[i + 1] then
            opts.named.key = parse_hex(args[i + 1]) -- parse_hex handles cleanup
            i = i + 2
        elseif arg == '--retry' and args[i + 1] then
            opts.named.retry = parse_number(args[i + 1])
            i = i + 2
        elseif arg == '--level' and args[i + 1] then
            opts.named.level = parse_number(args[i + 1], 16)
            i = i + 2
        elseif arg == '--usage' and args[i + 1] then
            opts.named.usage = parse_number(args[i + 1], 16)
            i = i + 2
        elseif arg == '--change' and args[i + 1] then
            opts.named.change = parse_number(args[i + 1], 16)
            i = i + 2
        elseif arg:sub(1, 1) == '-' then
            -- Unknown option, skip
            i = i + 1
        else
            -- Positional argument
            table.insert(opts.positional, arg)
            i = i + 1
        end
    end

    return opts
end

-- =============================================================================
-- Pre-command: Select and Authenticate
-- =============================================================================

local function do_pre_command(opts)
    -- Step 1: Select file if specified
    if opts.select_fid then
        local resp, sw1, sw2, err = fmcos.select_file(opts.select_fid, true)
        if not fmcos.check_sw(sw1, sw2) then
            return false
        end
    end

    -- Step 2: External auth if specified
    if opts.auth_kid and opts.auth_key then
        local ok, sw1, sw2, err = fmcos.fast_ext_auth(opts.auth_kid, opts.auth_key, true)
        if not ok then
            return false
        end
    end

    return true
end

-- =============================================================================
-- Command Handlers
-- =============================================================================

--- select <fid> or select -n <df_name>
local function cmd_select(opts)
    if opts.named.name then
        -- Select by DF name
        local resp, sw1, sw2, err = fmcos.select_df(opts.named.name, true)
        return fmcos.check_sw(sw1, sw2)
    elseif opts.positional[1] then
        local fid = parse_number(opts.positional[1], 16)
        local resp, sw1, sw2, err = fmcos.select_file(fid, true)
        return fmcos.check_sw(sw1, sw2)
    else
        fmcos.log_error("select: missing FID or -n <name>")
        return false
    end
end

--- read_binary <offset> <length>
local function cmd_read_binary(opts)
    if not do_pre_command(opts) then return false end

    local offset = parse_number(opts.positional[1]) or 0
    local length = parse_number(opts.positional[2]) or 16
    local sfi = opts.named.sfi

    local resp, sw1, sw2, err = fmcos.read_binary(offset, length, sfi, true)
    if resp then
        print(fmcos.hex_to_display(resp))
        return true
    end
    return false
end

--- update_binary <offset> <data>
local function cmd_update_binary(opts)
    if not do_pre_command(opts) then return false end

    if #opts.positional < 2 then
        fmcos.log_error("update_binary: offset and data required")
        return false
    end

    local offset = parse_number(opts.positional[1]) or 0
    local data = parse_hex(opts.positional[2])
    local sfi = opts.named.sfi

    local ok, sw1, sw2, err = fmcos.update_binary(offset, data, sfi, true)
    return ok
end

--- read_record <rec_num>
local function cmd_read_record(opts)
    if not do_pre_command(opts) then return false end

    local rec_num = parse_number(opts.positional[1]) or 1
    local sfi = opts.named.sfi

    local resp, sw1, sw2, err = fmcos.read_record(rec_num, sfi, 0, true)
    if resp then
        print(fmcos.hex_to_display(resp))
        return true
    end
    return false
end

--- update_record <rec_num> <data>
local function cmd_update_record(opts)
    if not do_pre_command(opts) then return false end

    if #opts.positional < 2 then
        fmcos.log_error("update_record: rec_num and data required")
        return false
    end

    local rec_num = parse_number(opts.positional[1]) or 1
    local data = parse_hex(opts.positional[2])
    local sfi = opts.named.sfi

    local ok, sw1, sw2, err = fmcos.update_record(rec_num, data, sfi, true)
    return ok
end

--- ext_auth <kid> <key> (or -a <kid> -k <key>)
local function cmd_ext_auth(opts)
    -- Select first if specified
    if opts.select_fid then
        local resp, sw1, sw2, err = fmcos.select_file(opts.select_fid, true)
        if not fmcos.check_sw(sw1, sw2) then
            return false
        end
    end

    local kid = opts.auth_kid or parse_number(opts.positional[1], 16)
    local key = opts.auth_key or parse_hex(opts.positional[2])

    if not kid or not key then
        fmcos.log_error("ext_auth: -a <kid> and -k <key> required")
        return false
    end

    -- If pre-command already authenticated using these same keys, we might be re-authing.
    -- But since command is explicit ext_auth, we do it anyway.

    local ok, sw1, sw2, err = fmcos.fast_ext_auth(kid, key, true)
    return ok
end

--- verify <kid> <pin>
local function cmd_verify(opts)
    if not do_pre_command(opts) then return false end

    local kid = parse_number(opts.positional[1], 16)
    local pin = nil

    if opts.named.pin then
        -- ASCII PIN provided via --pin
        pin = ascii_to_hex(opts.named.pin)
        fmcos.log("Using ASCII PIN: " .. opts.named.pin .. " -> " .. pin)
    else
        -- Hex PIN provided positionally
        pin = parse_hex(opts.positional[2])
    end

    if not kid or not pin then
        fmcos.log_error("verify: key_id and pin required (hex positional or --pin <str>)")
        return false
    end

    local _, ok, sw1, sw2, err = fmcos.verify_pin(kid, pin, true)
    return ok
end

--- challenge [length]
local function cmd_challenge(opts)
    if not do_pre_command(opts) then return false end

    local length = parse_number(opts.positional[1]) or 8
    local resp, sw1, sw2, err = fmcos.get_challenge(length, true)
    return resp ~= nil
end

--- create_file --type <type> [options] <args...>
--- Types: df, binary, fixed, variable, cyclic, key
local function cmd_create_file(opts)
    if not do_pre_command(opts) then return false end

    local file_type = opts.named.type
    if not file_type then
        fmcos.log_error("create_file: --type required (df, binary, fixed, variable, cyclic, key)")
        return false
    end

    if file_type == 'df' then
        -- create_file --type df <fid> <space> [name]
        local fid = parse_number(opts.positional[1], 16)
        local space = parse_number(opts.positional[2], 16) or 0x08
        local df_name = opts.positional[3] and parse_hex(opts.positional[3]) or ""
        local perm = opts.named.perm

        if not fid then
            fmcos.log_error("create_file df: FID required")
            return false
        end

        local ok, sw1, sw2, err = fmcos.create_df(fid, space, df_name, perm, true)
        return ok
    elseif file_type == 'key' then
        -- create_file --type key <slots> [perm]
        local slots = parse_number(opts.positional[1]) or 8
        local perm = opts.named.perm

        local ok, sw1, sw2, err = fmcos.create_key_file(0x0000, slots, perm, true)
        return ok
    elseif file_type == 'binary' then
        -- create_file --type binary <fid> <size>
        local fid = parse_number(opts.positional[1], 16)
        local size = parse_number(opts.positional[2])

        if not fid or not size then
            fmcos.log_error("create_file binary: FID and size required")
            return false
        end

        local options = { sfi = opts.named.sfi, perm = opts.named.perm }
        local ok, sw1, sw2, err = fmcos.create_file(fmcos.FILE_TYPE_BINARY, fid, size, options, true)
        return ok
    elseif file_type == 'fixed' or file_type == 'variable' or file_type == 'cyclic' then
        -- create_file --type <type> <fid> <rec_len> <rec_count>
        local fid = parse_number(opts.positional[1], 16)
        local rec_len = parse_number(opts.positional[2])
        local rec_count = parse_number(opts.positional[3]) or 10

        if not fid or not rec_len then
            fmcos.log_error("create_file record: FID and record_length required")
            return false
        end

        local type_map = {
            fixed = fmcos.FILE_TYPE_FIXED_RECORD,
            variable = fmcos.FILE_TYPE_VARIABLE_RECORD,
            cyclic = fmcos.FILE_TYPE_CYCLIC_RECORD
        }
        local options = { sfi = opts.named.sfi, record_count = rec_count }
        local ok, sw1, sw2, err = fmcos.create_file(type_map[file_type], fid, rec_len, options, true)
        return ok
    else
        fmcos.log_error("create_file: unknown type: " .. file_type)
        return false
    end
end

--- write_key <kid> [key_data]
local function cmd_write_key(opts)
    if not do_pre_command(opts) then return false end

    local kid = parse_number(opts.positional[1], 16)
    if not kid then
        fmcos.log_error("write_key: key_id required")
        return false
    end

    local key_data = nil
    local key_type = nil
    local add_mode = false

    -- Handle smart construction based on --type
    if opts.named.type then
        add_mode = true
        local t_str = opts.named.type
        local usage = opts.named.usage or 0xF0
        local change = opts.named.change or 0xF0
        local level = opts.named.level or 0x0F
        local retry = opts.named.retry or 3

        -- Safe counter packing: High nibble for max, low for current
        local counter_byte = ((retry & 0x0F) << 4) | (retry & 0x0F)

        if t_str == 'pin' then
            -- PIN Key (0x3A)
            -- Data: 3A Usage Change Level Counter PIN
            local pin_hex = nil
            if opts.named.pin then
                pin_hex = ascii_to_hex(opts.named.pin)
            elseif opts.positional[2] then
                pin_hex = parse_hex(opts.positional[2])
            end

            if not pin_hex then
                fmcos.log_error("write_key: --pin <str> or hex data required for PIN")
                return false
            end

            key_data = string.format("3A%02X%02X%02X%02X%s",
                usage, change, level, counter_byte, pin_hex)

            fmcos.log("Constructing PIN Data: " .. key_data)
        elseif t_str == 'ext_auth' or t_str == 'master' or t_str == 'des' then
            -- Ext Auth Key (0x39)
            -- Data: 39 Usage Change Level Counter Key
            local k_hex = opts.named.key or parse_hex(opts.positional[2])
            if not k_hex then
                fmcos.log_error("write_key: --key <hex> required for Key")
                return false
            end

            key_data = string.format("39%02X%02X%02X%02X%s",
                usage, change, level, counter_byte, k_hex)

            fmcos.log("Constructing Key Data: " .. key_data)
        else
            fmcos.log_error("Unknown key type: " .. t_str)
            return false
        end
    else
        -- Raw mode: write_key <kid> <key_data>
        key_data = parse_hex(opts.positional[2])
        if not key_data then
            fmcos.log_error("write_key: key_data required (or use --type)")
            return false
        end
        -- If just key data is provided, assume it is Update Key mode (not Add)
        -- unless it looks like a full structure?
        -- FMCOS.write_key handles add_mode vs update based on explicit param
        -- Here user provides raw blob, so we pass it through.
        add_mode = true -- Assuming adding/updating full blob by default if raw
    end

    local ok, sw1, sw2, err = fmcos.write_key(kid, key_data, add_mode, nil, true)
    return ok
end

--- erase_df
local function cmd_erase_df(opts)
    if not do_pre_command(opts) then return false end

    local ok, sw1, sw2, err = fmcos.erase_df(true)
    return ok
end

--- balance [type]
local function cmd_balance(opts)
    if not do_pre_command(opts) then return false end

    local app_type = parse_number(opts.positional[1], 16) or 0x02
    local balance, sw1, sw2, err = fmcos.get_balance(app_type, true)
    return balance ~= nil
end

--- apdu <hex>
local function cmd_apdu(opts)
    -- Use common pre-command logic to support -s (Select) and -a/-k (Auth)
    if not do_pre_command(opts) then return false end

    local apdu_hex = opts.positional[1]
    if not apdu_hex then
        fmcos.log_error("apdu: hex string required")
        return false
    end

    fmcos.log("Sending Raw APDU: " .. apdu_hex)
    local resp, sw1, sw2, err = fmcos.send_apdu_raw(apdu_hex, true)

    return fmcos.check_sw(sw1, sw2)
end

--- run -f <script_file>
local function cmd_run(opts)
    local filename = opts.named.file
    if not filename then
        fmcos.log_error("run: -f <script_file> required")
        return false
    end

    fmcos.log("Executing script: " .. filename)

    local file = io.open(filename, 'r')
    if not file then
        fmcos.log_error("Cannot open script file: " .. filename)
        return false
    end

    local line_num = 0
    local failed = 0
    local total = 0

    for line in file:lines() do
        line_num = line_num + 1
        line = line:gsub('^%s+', ''):gsub('%s+$', '') -- trim

        if #line > 0 and line:sub(1, 1) ~= '#' then
            total = total + 1
            fmcos.log(string.format("[%d] %s", line_num, line))

            -- Parse line as: command [args...]
            local parts = split(line, ' ')
            local cmd = parts[1]:lower()

            -- Build args for command
            local cmd_args = {}
            for i = 2, #parts do
                table.insert(cmd_args, parts[i])
            end
            local cmd_opts = parse_common_options(cmd_args, 1)

            -- Execute command
            local ok = false
            if COMMANDS[cmd] then
                ok = COMMANDS[cmd](cmd_opts)
            elseif cmd == 'apdu' or cmd == 'raw' then
                -- Raw APDU
                local apdu_hex = ""
                for i = 2, #parts do
                    apdu_hex = apdu_hex .. parse_hex(parts[i])
                end
                fmcos.log("RAW APDU: " .. fmcos.hex_to_display(apdu_hex))
                local resp, sw1, sw2, err = fmcos.send_apdu_raw(apdu_hex, true)
                ok = sw1 and sw2 and fmcos.check_sw(sw1, sw2)
            else
                fmcos.log_warn("Unknown command: " .. cmd)
                ok = true -- Continue
            end

            if not ok then
                failed = failed + 1
                fmcos.log_warn("  Command failed, continuing...")
            end
        end
    end

    file:close()

    print()
    if failed == 0 then
        fmcos.log_success(string.format("Script completed: %d commands executed", total))
    else
        fmcos.log_warn(string.format("Script completed: %d/%d succeeded", total - failed, total))
    end

    return failed == 0
end

--- explore [--mode ef|df] [--start XXXX] [--end XXXX]
--- Scans file system for EFs or DFs in given range
local function cmd_explore(opts)
    if not do_pre_command(opts) then return false end

    local mode = opts.named.mode or 'ef'
    mode = mode:lower()

    -- Determine range based on mode
    local start_fid, end_fid
    if mode == 'df' then
        start_fid = opts.named.start and parse_number(opts.named.start, 16) or 0xDF01
        end_fid = opts.named['end'] and parse_number(opts.named['end'], 16) or 0xDF10
    else
        -- EF mode (default)
        start_fid = opts.named.start and parse_number(opts.named.start, 16) or 0x0000
        end_fid = opts.named['end'] and parse_number(opts.named['end'], 16) or 0x0020
    end

    fmcos.log(string.format("Exploring %s Range %04X-%04X...", mode:upper(), start_fid, end_fid))
    fmcos.log(string.rep("-", 60))
    fmcos.log(string.format("%-6s %-18s %-6s %-30s", "FID", "Type", "Size", "Name/Info"))
    fmcos.log(string.rep("-", 60))


    local found_count = 0
    local base_fid = opts.select_fid or 0x3F00

    for fid = start_fid, end_fid do
        -- Try to select the file (silent mode)
        local resp, sw1, sw2, err = fmcos.select_file(fid, true, true)

        if fmcos.check_sw(sw1, sw2) then
            found_count = found_count + 1

            -- Identify file type from response
            local f_type = "Unknown"
            local size_str = "-"
            local info_str = ""

            -- Check FCI
            local type_byte = nil
            if resp and #resp >= 2 then
                type_byte = tonumber(resp:sub(1, 2), 16)

                if type_byte == 0x38 then
                    f_type = "DF"
                    -- Try to extract DF name from FCI
                    if #resp >= 4 then
                        -- Find 84 tag (DF name)
                        local pos = resp:find("84")
                        if pos then
                            local len = tonumber(resp:sub(pos + 2, pos + 3), 16) or 0
                            if len > 0 and pos + 4 + len * 2 <= #resp + 1 then
                                local name_hex = resp:sub(pos + 4, pos + 3 + len * 2)
                                -- Convert hex to ASCII
                                local name = ""
                                for i = 1, #name_hex, 2 do
                                    local byte = tonumber(name_hex:sub(i, i + 1), 16)
                                    if byte and byte >= 0x20 and byte < 0x7F then
                                        name = name .. string.char(byte)
                                    end
                                end
                                if #name > 0 then
                                    info_str = "Name: " .. name
                                end
                            end
                        end
                    end
                elseif type_byte == 0x28 then
                    f_type = "Binary EF"
                elseif type_byte == 0x2A then
                    f_type = "Fixed Record EF"
                elseif type_byte == 0x2C then
                    f_type = "Variable Record EF"
                elseif type_byte == 0x2E then
                    f_type = "Cyclic Record EF"
                elseif type_byte == 0x2F then
                    f_type = "E-Purse/Wallet"
                elseif type_byte == 0x3F then
                    f_type = "Key File"
                elseif type_byte == 0x6F then
                    -- FCI template - likely DF
                    f_type = "DF (FCI)"
                    -- Parse FCI tags
                    if resp:find("84") then
                        local pos = resp:find("84")
                        local len = tonumber(resp:sub(pos + 2, pos + 3), 16) or 0
                        if len > 0 then
                            local name_hex = resp:sub(pos + 4, pos + 3 + len * 2)
                            local name = ""
                            for i = 1, #name_hex, 2 do
                                local byte = tonumber(name_hex:sub(i, i + 1), 16)
                                if byte and byte >= 0x20 and byte < 0x7F then
                                    name = name .. string.char(byte)
                                end
                            end
                            if #name > 0 then
                                info_str = "Name: " .. name
                            end
                        end
                    end
                end

                -- Try to extract size (bytes 2-3 for some file types)
                if #resp >= 6 and type_byte ~= 0x6F and type_byte ~= 0x38 then
                    local size_hex = resp:sub(3, 6)
                    local size_val = tonumber(size_hex, 16)
                    if size_val and size_val < 65536 then
                        size_str = tostring(size_val)
                    end
                end
            end

            -- Fallback probing if Unknown
            if f_type == "Unknown" then
                -- Try Read Binary
                local bin_resp, bin_sw1, bin_sw2, _ = fmcos.read_binary(0, 1, nil, true, true)
                if fmcos.check_sw(bin_sw1, bin_sw2) then
                    f_type = "Binary EF (Est)"
                elseif bin_sw1 == 0x69 and bin_sw2 == 0x86 then -- Command not allowed (no current EF)
                    f_type = "DF (Likely)"
                else
                    -- Try Read Record
                    local rec_resp, rec_sw1, rec_sw2, _ = fmcos.read_record(1, nil, 0, true, true)
                    if fmcos.check_sw(rec_sw1, rec_sw2) then
                        f_type = "Record EF (Est)"
                    elseif rec_sw1 == 0x69 and rec_sw2 == 0x86 then
                        f_type = "DF (Likely)"
                    end
                end
            end

            fmcos.log(string.format("%04X   %-18s %-6s %-30s", fid, f_type, size_str, info_str))

            -- Return to base DF for next iteration
            if base_fid then
                fmcos.select_file(base_fid, true, true)
            end
        end
    end

    fmcos.log(string.rep("-", 60))
    fmcos.log_success(string.format("Found %d files", found_count))

    return true
end

-- =============================================================================
-- Command Registry
-- =============================================================================

--- read_record <rec_num> [len]
local function cmd_read_record(opts)
    if not do_pre_command(opts) then return false end

    local rec_num = parse_number(opts.positional[1])
    if not rec_num then
        fmcos.log_error("read_record: <rec_num> required")
        return false
    end

    local len = parse_number(opts.positional[2]) -- Optional length

    local resp, sw1, sw2, err = fmcos.read_record(rec_num, opts.named.sfi, len, true)
    if resp then
        print(fmcos.hex_to_display(resp))
        return true
    end
    return false
end

--- internal_auth <kid> <data>
local function cmd_internal_auth(opts)
    if not do_pre_command(opts) then return false end
    local kid = parse_number(opts.positional[1], 16)
    local data = parse_hex(opts.positional[2])
    if not kid or not data then
        fmcos.log_error("internal_auth: <kid> <data> required"); return false
    end
    local resp, sw1, sw2, err = fmcos.internal_authenticate(0x00, kid, data, true)
    if resp then
        print(fmcos.hex_to_display(resp))
        return true
    end
    return false
end

--- append_record <data> [--sfi <sfi>]
local function cmd_append_record(opts)
    if not do_pre_command(opts) then return false end
    local data = parse_hex(opts.positional[1])
    if not data then
        fmcos.log_error("append_record: <data> required"); return false
    end
    local ok, sw1, sw2, err = fmcos.append_record(data, opts.named.sfi, true)
    return ok
end

--- change_pin <kid> <old_hex> <new_hex> (OR --mode reload <kid> <new> <key>)
local function cmd_change_pin(opts)
    if not do_pre_command(opts) then return false end
    local kid = parse_number(opts.positional[1], 16)
    local arg1 = parse_hex(opts.positional[2])
    local arg2 = parse_hex(opts.positional[3])

    if not kid or not arg1 or not arg2 then
        fmcos.log_error(
            "Usage:\n  change_pin <kid> <old_hex> <new_hex>\n  change_pin --mode reload <kid> <new_hex> <key_hex>")
        return false
    end

    if opts.named.mode == 'reload' then
        -- Reload PIN (Admin)
        local ok, sw1, sw2, err = fmcos.reload_pin(kid, arg1, arg2, true)
        return ok
    else
        -- User Change
        local ok, sw1, sw2, err = fmcos.modify_pin(kid, arg1, arg2, true)
        return ok
    end
end

--- unlock_pin <kid> <new_pin_hex> <key_hex>
local function cmd_unlock_pin(opts)
    if not do_pre_command(opts) then return false end
    local kid = parse_number(opts.positional[1], 16)
    local new = parse_hex(opts.positional[2])
    local key = parse_hex(opts.positional[3])
    if not kid or not new or not key then
        fmcos.log_error("unlock_pin: <kid> <new_pin_hex> <ukey_hex> required")
        return false
    end
    local ok, sw1, sw2, err = fmcos.unlock_pin(kid, new, key, true)
    return ok
end

--- card_block <key_hex>
local function cmd_card_block(opts)
    if not do_pre_command(opts) then return false end
    local key = parse_hex(opts.positional[1])
    if not key then
        fmcos.log_error("card_block: <key_hex> required"); return false
    end
    local ok, sw1, sw2, err = fmcos.card_block(key, true)
    return ok
end

local COMMANDS = {
    select = cmd_select,
    read_binary = cmd_read_binary,
    update_binary = cmd_update_binary,
    read_record = cmd_read_record,
    update_record = cmd_update_record,
    append_record = cmd_append_record,
    ext_auth = cmd_ext_auth,
    internal_auth = cmd_internal_auth,
    verify = cmd_verify,
    change_pin = cmd_change_pin,
    unlock_pin = cmd_unlock_pin,
    card_block = cmd_card_block,
    challenge = cmd_challenge,
    create_file = cmd_create_file,
    write_key = cmd_write_key,
    erase_df = cmd_erase_df,
    balance = cmd_balance,
    apdu = cmd_apdu,
    explore = cmd_explore,
    run = cmd_run,
}

-- =============================================================================
-- Help
-- =============================================================================

-- =============================================================================
-- Help System (NetExec Style)
-- =============================================================================

local COMMAND_HELP = {
    select = [[
Usage: select [options] <fid>
       select -n <name>

Select a file by File ID (FID) or DF by Name.

Options:
    -n <name>       Select DF by application name (string)
    -s <fid>        (Common) Select parent first
]],
    read_binary = [[
Usage: read_binary [options] <offset> <len>

Read binary data from the currently selected or specified EF.

Arguments:
    offset          Start offset (hex or dec)
    len             Number of bytes to read

Options:
    -s <fid>        Select file first
    -a <kid>        Auth with Key ID before read
    -k <key>        Auth Key Value
]],
    update_binary = [[
Usage: update_binary [options] <offset> <data>

Write binary data to the currently selected or specified EF.

Arguments:
    offset          Start offset
    data            Hex string data to write

Options:
    -s <fid>        Select file first
    -a <key_id>     Auth Key ID
    -k <key>        Auth Key
]],
    read_record = [[
Usage: read_record [options] <rec_num> [len]

Read a record from a Record EF.

Arguments:
    rec_num         Record Number (1-based)
    len             Length to read (optional, default=256/00)

Options:
    -s <fid>        Select file first
    --sfi <sfi>     Use Short File Identifier (SFI) for access
]],
    update_record = [[
Usage: update_record [options] <rec_num> <data>

Update a record in a Record EF.

Arguments:
    rec_num         Record Number
    data            Hex string data

Options:
    -s <fid>        Select file first
    --sfi <sfi>     Use Short File Identifier (SFI)
]],
    create_file = [[
Usage: create_file --type <type> [options] <fid_or_args...>

Create a new file in the current DF.

Types:
    df              Create Dedicated File (DF)
                    Args: <fid> <space> [name]
    binary          Create Binary EF
                    Args: <fid> <size>
    fixed           Create Fixed Record EF
                    Args: <fid> <rec_len> <rec_count>
                    (Note: Perms default to FFFFFFFFFF, SFI default 01)
    cyclic          Create Cyclic Record EF
                    Args: <fid> <rec_len> <rec_count>
    key             Create Key File
                    Args: <slots>

Options:
    --perm <hex>    Permission bytes (5 bytes, default FFFFFFFFFF)
    --sfi <val>     SFI value (Record files only, default 01)
]],
    write_key = [[
Usage: write_key [options] <kid> [data]

Write or Update a Key or PIN.

Options:
    --type <type>   Key type: pin, ext_auth, master
    --pin <str>     PIN value (String)
    --key <hex>     Key value (Hex)
    --level <hex>   Security Level (default 0F)
]],
    verify = [[
Usage: verify <kid> --pin <str>

Verify a PIN.
]],
    explore = [[
Usage: explore [options]

Scan for valid FIDs in range.

Options:
    --mode ef|df    Scan EFs or DFs (default: ef)
    --start <fid>   Start FID
    --end <fid>     End FID
]],
    run = [[
Usage: run -f <file>

Execute a script file containing hf_fmcos commands.
]],
    apdu = [[
Usage: apdu <hex>

Send a raw APDU to the card (useful for debugging).
]],
    ext_auth = [[
Usage: ext_auth <kid> <key>

Perform External Authentication.
]],
    erase_df = [[
Usage: erase_df

Erase the currently selected Dedicated File (DF).
]],
    balance = [[
Usage: balance [type]

Get Electronic Purse/Wallet balance.
Type: 01 (Passbook), 02 (Purse). Default 02.
]],
    challenge = [[
Usage: challenge [len]

Get a random challenge from the card.
]],
    internal_auth = [[
Usage: internal_auth [options] <kid> <data_hex>

Perform Internal Authentication (Compute MAC/Cryptogram).
]],
    append_record = [[
Usage: append_record [options] <data_hex>

Append data as a new record (Cyclic/Variable EF).
]],
    change_pin = [[
Usage: change_pin <kid> <old_hex> <new_hex>
       change_pin --mode reload <kid> <new_hex> <key_hex>

Change User PIN (using Old PIN) or Reload PIN (using Admin Key).
]],
    unlock_pin = [[
Usage: unlock_pin <kid> <new_pin_hex> <unlock_key_hex>

Unblock a locked PIN using the Unlock Key.
]],
    card_block = [[
Usage: card_block <key_hex>

Block the entire card using Line Protection Key.
]]
}

local function help(cmd_name)
    print(copyright)
    print(desc)
    print("")

    if cmd_name and COMMAND_HELP[cmd_name] then
        print(ansicolors.cyan .. "Command: " .. cmd_name .. ansicolors.reset)
        print(COMMAND_HELP[cmd_name])

        print(ansicolors.cyan .. "\nCommon Options:" .. ansicolors.reset)
        print("    -s <fid>     Select file first")
        print("    -a <kid>     External Auth Key ID")
        print("    -k <key>     External Auth Key (Hex)")
        print("    -d           Enable debug output")
        return
    end

    print(ansicolors.cyan .. "Available Commands:" .. ansicolors.reset)
    local cmds = {}
    for k, v in pairs(COMMAND_HELP) do table.insert(cmds, k) end
    table.sort(cmds)

    -- Print in columns or list
    for _, k in ipairs(cmds) do
        print(string.format("    %-15s", k))
    end
    print("")
    print("Use 'hf_fmcos <command> --help' for command-specific usage.")
end

-- =============================================================================
-- Main
-- =============================================================================

function main(args)
    -- Parse args from PM3
    local args_table = {}
    if type(args) == "string" and #args > 0 then
        for part in args:gmatch('%S+') do
            table.insert(args_table, part)
        end
    elseif type(args) == "table" then
        args_table = args
    end

    -- No Args -> Global Help
    if #args_table == 0 then
        return help(nil)
    end

    -- Global Help flag?
    if args_table[1] == '-h' or args_table[1] == '--help' then
        return help(nil)
    end

    local cmd_name = args_table[1]:lower()

    -- Check for sub-command help (e.g. create_file --help)
    for _, arg in ipairs(args_table) do
        if arg == '-h' or arg == '--help' then
            return help(cmd_name)
        end
    end

    -- Validate command
    if not COMMANDS[cmd_name] then
        fmcos.log_error("Unknown command: " .. cmd_name)
        help(nil) -- Show list
        return
    end

    -- Parse Options (excluding cmd_name which is at index 1 generally, but parse_common_options handles skip)
    local opts = parse_common_options(args_table, 2)
    fmcos.set_debug(opts.debug)

    -- Connect
    local card_info, err = fmcos.connect()
    if not card_info then
        return
    end

    -- Execute
    local ok = COMMANDS[cmd_name](opts)

    fmcos.disconnect()

    if ok then
        -- fmcos.log_success("Done") -- clean output
    end
end

-- Entry point
main(args)
