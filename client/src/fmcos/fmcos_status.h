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
// FMCOS Status Words Definition
//-----------------------------------------------------------------------------

#ifndef _FMCOS_STATUS_H_
#define _FMCOS_STATUS_H_

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Get human-readable description for FMCOS ISO 7816-4 status words
 * @param sw1 Status byte 1
 * @param sw2 Status byte 2
 * @return String description of the status word
 */
const char* fmcos_status_to_string(uint8_t sw1, uint8_t sw2);

/**
 * @brief Check if status word means success (9000 or successfully completed)
 * @param sw1 Status byte 1
 * @param sw2 Status byte 2
 * @return True if successful
 */
bool fmcos_status_is_ok(uint8_t sw1, uint8_t sw2);

#endif // _FMCOS_STATUS_H_
