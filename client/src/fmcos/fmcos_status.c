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
// FMCOS Status Words Implementation
//-----------------------------------------------------------------------------

#include "fmcos_status.h"

const char* fmcos_status_to_string(uint8_t sw1, uint8_t sw2) {
    uint16_t sw = (sw1 << 8) | sw2;
    switch (sw) {
        case 0x9000: return "Success";
        case 0x6281: return "Part of data may be corrupted (Returned bytes may be less than expected)";
        case 0x6283: return "Selected file invalidated";
        case 0x6300: return "Authentication failed";
        case 0x6500: return "State changed, EEPROM update failed";
        case 0x6581: return "Memory failure";
        case 0x6700: return "Wrong length (Lc/Le incorrect)";
        case 0x6882: return "Secure messaging not supported";
        case 0x6900: return "Transaction uninitialized";
        case 0x6901: return "Transaction amount error";
        case 0x6981: return "Command incompatible with file structure";
        case 0x6982: return "Security status not satisfied";
        case 0x6983: return "Authentication method blocked";
        case 0x6984: return "Referenced data invalidated";
        case 0x6985: return "Conditions of use not satisfied";
        case 0x6986: return "Command not allowed (no EF selected)";
        case 0x6987: return "Secure messaging data object missing";
        case 0x6988: return "Secure messaging data object incorrect (MAC error)";
        case 0x6A80: return "Incorrect parameters in data field";
        case 0x6A81: return "Function not supported";
        case 0x6A82: return "File not found";
        case 0x6A83: return "Record not found";
        case 0x6A84: return "Not enough memory space in file";
        case 0x6A86: return "Incorrect parameters P1-P2";
        case 0x6A88: return "Referenced data not found (Key not found)";
        case 0x6B00: return "Wrong parameter(s) P1-P2";
        case 0x6E00: return "Class not supported";
        case 0x6F00: return "No precise diagnosis";
        case 0x9302: return "MAC error (PBOC/FMCOS proprietary)";
        case 0x9303: return "Application locked (PBOC/FMCOS proprietary)";
        case 0x9401: return "Insufficient balance (PBOC/FMCOS proprietary)";
        case 0x9403: return "Key not found (PBOC/FMCOS proprietary)";
        case 0x9406: return "Required MAC not available (PBOC/FMCOS proprietary)";
        default: 
            // Handle 63CX for PIN retries
            if (sw1 == 0x63 && (sw2 & 0xF0) == 0xC0) {
                return "Verification failed (retries remaining in SW2 low nibble)";
            }
            return "Unknown";
    }
}

bool fmcos_status_is_ok(uint8_t sw1, uint8_t sw2) {
    if (sw1 == 0x90 && sw2 == 0x00) return true;
    if (sw1 == 0x61) return true; // 61XX is normal processing (Response bytes still available)
    return false;
}
