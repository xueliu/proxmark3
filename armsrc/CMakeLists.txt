#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------

# This file is part of the Proxmark3 project.
# It contains the CMake build logic for the ARM firmware.

# Set include directories
# Corresponds to the INCLUDE variable in common_arm/Makefile.common
include_directories(
    "."
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common_arm"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common_fpga"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/crapto1"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/mbedtls"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/lz4"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/hitag2"
)

# --- Platform and feature selection ---
# The following options correspond to the PLATFORM, PLATFORM_EXTRAS, and SKIP_*
# variables in the Makefiles.

option(SKIP_LF "Skip LF functionality" OFF)
option(SKIP_HITAG "Skip Hitag functionality" OFF)
option(SKIP_EM4x50 "Skip EM4x50 functionality" OFF)
option(SKIP_EM4x70 "Skip EM4x70 functionality" OFF)
option(SKIP_ZX8211 "Skip ZX8211 functionality" OFF)
option(SKIP_HF "Skip HF functionality" OFF)
option(SKIP_ISO15693 "Skip ISO15693 functionality" OFF)
option(SKIP_LEGICRF "Skip Legic-RF functionality" OFF)
option(SKIP_ISO14443b "Skip ISO14443b functionality" OFF)
option(SKIP_ISO14443a "Skip ISO14443a functionality" OFF)
option(SKIP_ICLASS "Skip iClass functionality" OFF)
option(SKIP_FELICA "Skip Felica functionality" OFF)
option(SKIP_NFCBARCODE "Skip NFC Barcode functionality" OFF)
option(SKIP_HFSNIFF "Skip HF Sniff functionality" OFF)
option(SKIP_HFPLOT "Skip HF Plot functionality" OFF)
option(SKIP_COMPRESSION "Skip compression" OFF)

# --- Compiler flags and definitions ---

# Base compiler flags
# Corresponds to DEFCFLAGS in common_arm/Makefile.common and APP_CFLAGS in armsrc/Makefile
add_compile_options(
    -Os -pedantic -fstrict-aliasing -pipe -Wall -Werror
    -ffunction-sections -fdata-sections -fno-stack-protector -fno-pie
    -Wbad-function-cast -Wchar-subscripts -Wundef -Wunused -Wuninitialized -Wpointer-arith -Wformat -Wformat-security -Winit-self -Wmissing-include-dirs -Wnested-externs -Wempty-body -Wignored-qualifiers -Wmissing-field-initializers -Wtype-limits
    -Wshadow -Wno-error=shadow
    -Winline -Wno-error=inline
    -Wmissing-prototypes -Wno-error=missing-prototypes
    -Wmissing-declarations  -Wno-error=missing-declarations
    -Wstrict-prototypes -Wno-error=strict-prototypes
)

# Set compiler definitions based on platform and features
# Corresponds to the PLATFORM_DEFS variable in common_arm/Makefile.hal
if(PLATFORM STREQUAL "PM3RDV4")
    add_compile_definitions(WITH_SMARTCARD WITH_FLASH RDV4)
elseif(PLATFORM STREQUAL "PM3GENERIC")
    # No specific defs for generic, but LED_ORDER could be added as an option
elseif(PLATFORM STREQUAL "PM3ICOPYX")
    add_compile_definitions(WITH_FLASH ICOPYX DXC3)
elseif(PLATFORM STREQUAL "PM3ULTIMATE")
    add_compile_definitions(WITH_FLASH DXC2S50)
endif()

# Platform extras
if(PLATFORM_EXTRAS_BTADDON)
    add_compile_definitions(WITH_FPC_USART_HOST)
endif()
if(PLATFORM_EXTRAS_FLASH)
    add_compile_definitions(WITH_FLASH)
endif()
if(PLATFORM_EXTRAS_SMARTCARD)
    add_compile_definitions(WITH_SMARTCARD)
endif()
if(PLATFORM_EXTRAS_FPC_USART_DEV)
    add_compile_definitions(WITH_FPC_USART_DEV)
endif()

# Add definitions based on SKIP_* options
if(NOT SKIP_LF)
    add_compile_definitions(WITH_LF)
endif()
if(NOT SKIP_HITAG)
    add_compile_definitions(WITH_HITAG)
endif()
if(NOT SKIP_EM4x50)
    add_compile_definitions(WITH_EM4x50)
endif()
if(NOT SKIP_EM4x70)
    add_compile_definitions(WITH_EM4x70)
endif()
if(NOT SKIP_ZX8211)
    add_compile_definitions(WITH_ZX8211)
endif()
if(NOT SKIP_HF)
    add_compile_definitions(WITH_GENERAL_HF)
endif()
if(NOT SKIP_ISO15693)
    add_compile_definitions(WITH_ISO15693)
endif()
if(NOT SKIP_LEGICRF)
    add_compile_definitions(WITH_LEGICRF)
endif()
if(NOT SKIP_ISO14443b)
    add_compile_definitions(WITH_ISO14443b)
endif()
if(NOT SKIP_ISO14443a)
    add_compile_definitions(WITH_ISO14443a)
endif()
if(NOT SKIP_ICLASS)
    add_compile_definitions(WITH_ICLASS)
endif()
if(NOT SKIP_FELICA)
    add_compile_definitions(WITH_FELICA)
endif()
if(NOT SKIP_NFCBARCODE)
    add_compile_definitions(WITH_NFCBARCODE)
endif()
if(NOT SKIP_HFSNIFF)
    add_compile_definitions(WITH_HFSNIFF)
endif()
if(NOT SKIP_HFPLOT)
    add_compile_definitions(WITH_HFPLOT)
endif()
if(NOT SKIP_COMPRESSION)
    add_compile_definitions(WITH_COMPRESSION)
endif()


# --- Source files ---
# The source files are added conditionally, based on the selected platform and features.
# This corresponds to the SRC_* variables in armsrc/Makefile.

set(FIRMWARE_SOURCES)
set(THUMB_SOURCES)
set(ARM_SOURCES)

list(APPEND FIRMWARE_SOURCES
    appmain.c
    BigBuf.c
    cmd.c
    dbprint.c
    fpgaloader.c
    hfsnoop.c
    printf.c
    start.c
    string.c
    util.c
    ../common/crc.c
    ../common/crc16.c
    ../common/crc32.c
    ../common/generator.c
    ../common/crapto1/crypto1.c
    ../common/crapto1/des.c
    ../common/mbedtls/aes.c
    ../common/mbedtls/platform_util.c
    ../common/lz4/lz4.c
    ../common_arm/clocks.c
    ../common_arm/commonutil.c
    ../common_arm/lfdemod.c
    ../common_arm/ticks.c
    ../common_arm/usb_cdc.c
    ../common_arm/version.c
)

list(APPEND THUMB_SOURCES
    appmain.c
    printf.c
    dbprint.c
    ../common_arm/commonutil.c
    util.c
    string.c
    BigBuf.c
    ../common_arm/ticks.c
    ../common_arm/clocks.c
    hfsnoop.c
    ../common/generator.c
    ../common/crc.c
    ../common/crc16.c
    ../common/crc32.c
    ../common/crapto1/crypto1.c
    ../common/crapto1/des.c
    ../common/mbedtls/aes.c
    ../common/mbedtls/platform_util.c
    ../common/lz4/lz4.c
    start.c
)

list(APPEND ARM_SOURCES
    fpgaloader.c
    ../common_arm/usb_cdc.c
    cmd.c
)

if(NOT SKIP_LF)
    list(APPEND FIRMWARE_SOURCES lfops.c lfsampling.c pcf7931.c lfadc.c)
    list(APPEND THUMB_SOURCES lfops.c lfsampling.c pcf7931.c lfadc.c)
endif()

if(NOT SKIP_HF)
    list(APPEND FIRMWARE_SOURCES hfops.c)
    list(APPEND THUMB_SOURCES hfops.c)
endif()

if(NOT SKIP_ISO15693)
    list(APPEND FIRMWARE_SOURCES iso15693.c ../common/iso15693tools.c)
    list(APPEND THUMB_SOURCES iso15693.c ../common/iso15693tools.c)
endif()

if(NOT SKIP_ISO14443a)
    list(APPEND FIRMWARE_SOURCES iso14443a.c mifareutil.c mifarecmd.c epa.c mifaresim.c sam_common.c sam_mfc.c sam_seos.c desfire_crypto.c mifaredesfire.c)
    list(APPEND THUMB_SOURCES iso14443a.c mifareutil.c mifarecmd.c epa.c mifaresim.c sam_common.c sam_mfc.c sam_seos.c desfire_crypto.c mifaredesfire.c)
endif()

if(NOT SKIP_ISO14443b)
    list(APPEND FIRMWARE_SOURCES iso14443b.c)
    list(APPEND THUMB_SOURCES iso14443b.c)
endif()

if(NOT SKIP_FELICA)
    list(APPEND FIRMWARE_SOURCES felica.c)
    list(APPEND THUMB_SOURCES felica.c)
endif()

if(NOT SKIP_ICLASS)
    list(APPEND FIRMWARE_SOURCES iclass.c optimized_cipherutils.c optimized_ikeys.c optimized_elite.c optimized_cipher.c sam_picopass.c)
    list(APPEND THUMB_SOURCES iclass.c optimized_cipherutils.c optimized_ikeys.c optimized_elite.c optimized_cipher.c sam_picopass.c)
endif()

if(NOT SKIP_LEGICRF)
    list(APPEND FIRMWARE_SOURCES legicrf.c legicrfsim.c ../common/legic_prng.c)
    list(APPEND THUMB_SOURCES legicrf.c legicrfsim.c ../common/legic_prng.c)
endif()

if(NOT SKIP_NFCBARCODE)
    list(APPEND FIRMWARE_SOURCES thinfilm.c)
    list(APPEND THUMB_SOURCES thinfilm.c)
endif()

if(PLATFORM_EXTRAS_FLASH OR PLATFORM STREQUAL "PM3RDV4" OR PLATFORM STREQUAL "PM3ICOPYX" OR PLATFORM STREQUAL "PM3ULTIMATE")
    list(APPEND FIRMWARE_SOURCES flashmem.c spiffs.c spiffs_cache.c spiffs_check.c spiffs_gc.c spiffs_nucleus.c spiffs_hydrogen.c)
    list(APPEND THUMB_SOURCES flashmem.c spiffs.c spiffs_cache.c spiffs_check.c spiffs_gc.c spiffs_nucleus.c spiffs_hydrogen.c)
endif()

if(PLATFORM_EXTRAS_SMARTCARD OR PLATFORM STREQUAL "PM3RDV4")
    list(APPEND FIRMWARE_SOURCES i2c.c i2c_direct.c emvsim.c)
    list(APPEND THUMB_SOURCES i2c.c i2c_direct.c emvsim.c)
endif()

if(PLATFORM_EXTRAS_FPC_USART_HOST OR PLATFORM_EXTRAS_FPC_USART_DEV)
    list(APPEND FIRMWARE_SOURCES usart.c)
    list(APPEND THUMB_SOURCES usart.c)
endif()

if(NOT SKIP_HITAG)
    list(APPEND FIRMWARE_SOURCES ../common/hitag2/hitag2_crypto.c hitag_common.c hitag2.c hitagS.c hitagu.c hitag2_crack.c)
    list(APPEND THUMB_SOURCES ../common/hitag2/hitag2_crypto.c hitag_common.c hitag2.c hitagS.c hitagu.c hitag2_crack.c)
endif()

if(NOT SKIP_EM4x50)
    list(APPEND FIRMWARE_SOURCES em4x50.c ../common/bruteforce.c)
    list(APPEND THUMB_SOURCES em4x50.c ../common/bruteforce.c)
endif()

if(NOT SKIP_EM4x70)
    list(APPEND FIRMWARE_SOURCES em4x70.c)
    list(APPEND THUMB_SOURCES em4x70.c)
endif()

if(NOT SKIP_ZX8211)
    list(APPEND FIRMWARE_SOURCES lfzx.c)
    list(APPEND THUMB_SOURCES lfzx.c)
endif()

# Set compilation mode (Thumb vs ARM) for source files
set_source_files_properties(${THUMB_SOURCES} PROPERTIES COMPILE_FLAGS "-mthumb")
set_source_files_properties(${ARM_SOURCES} PROPERTIES COMPILE_FLAGS "-marm")

# --- Custom commands for build process ---

# FPGA bitstream compression
find_program(FPGA_COMPRESSOR_EXECUTABLE fpga_compress HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../tools/fpga_compress")
if(NOT FPGA_COMPRESSOR_EXECUTABLE)
    message(FATAL_ERROR "fpga_compress not found. Please build it first by running 'make fpga_compress' in the root directory.")
endif()

set(FPGA_BITSTREAMS)
if(PLATFORM STREQUAL "PM3RDV4" OR PLATFORM STREQUAL "PM3GENERIC")
    list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_hf.bit")
    if(NOT SKIP_LF)
        list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_lf.bit")
    endif()
    if(NOT SKIP_FELICA)
        list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_felica.bit")
    endif()
    if(NOT SKIP_ISO15693)
        list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_hf_15.bit")
    endif()
elseif(PLATFORM STREQUAL "PM3ICOPYX")
    list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_icopyx_hf.bit")
elseif(PLATFORM STREQUAL "PM3ULTIMATE")
    list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_ult_hf.bit")
    if(NOT SKIP_LF)
        list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_ult_lf.bit")
    endif()
    if(NOT SKIP_FELICA)
        list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_ult_felica.bit")
    endif()
    if(NOT SKIP_ISO15693)
        list(APPEND FPGA_BITSTREAMS "${CMAKE_CURRENT_SOURCE_DIR}/../fpga/fpga_pm3_ult_hf_15.bit")
    endif()
endif()

set(FPGA_VERSION_INFO_C "${CMAKE_CURRENT_BINARY_DIR}/fpga_version_info.c")
add_custom_command(
    OUTPUT ${FPGA_VERSION_INFO_C}
    COMMAND ${FPGA_COMPRESSOR_EXECUTABLE} -v ${FPGA_BITSTREAMS} ${FPGA_VERSION_INFO_C}
    DEPENDS ${FPGA_BITSTREAMS}
    COMMENT "Generating FPGA version info"
)
list(APPEND FIRMWARE_SOURCES ${FPGA_VERSION_INFO_C})

set(FPGA_ALL_BIT_Z "${CMAKE_CURRENT_BINARY_DIR}/fpga_all.bit.z")
add_custom_command(
    OUTPUT ${FPGA_ALL_BIT_Z}
    COMMAND ${FPGA_COMPRESSOR_EXECUTABLE} ${FPGA_BITSTREAMS} ${FPGA_ALL_BIT_Z}
    DEPENDS ${FPGA_BITSTREAMS}
    COMMENT "Compressing FPGA bitstreams"
)

set(FPGA_ALL_O "${CMAKE_CURRENT_BINARY_DIR}/fpga_all.o")
add_custom_command(
    OUTPUT ${FPGA_ALL_O}
    COMMAND ${CMAKE_OBJCOPY} -O elf32-littlearm -I binary -B arm --prefix-sections=fpga_all_bit ${FPGA_ALL_BIT_Z} ${FPGA_ALL_O}
    DEPENDS ${FPGA_ALL_BIT_Z}
    COMMENT "Generating FPGA object file"
)

# Version info generation
# Corresponds to the mkversion.sh script in armsrc/Makefile
find_program(SH_EXECUTABLE sh)
set(VERSION_PM3_C "${CMAKE_CURRENT_BINARY_DIR}/version_pm3.c")
add_custom_command(
    OUTPUT ${VERSION_PM3_C}
    COMMAND ${SH_EXECUTABLE} ../tools/mkversion.sh ${VERSION_PM3_C}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
    COMMENT "Generating version info with mkversion.sh"
    VERBATIM
)
list(APPEND FIRMWARE_SOURCES ${VERSION_PM3_C})


# --- Executable and post-build steps ---

# Linker script
set(LD_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/ldscript")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T ${LD_SCRIPT}")

# Add the executable
add_executable(fullimage.elf ${FIRMWARE_SOURCES} ${FPGA_ALL_O})
target_link_libraries(fullimage.elf -lgcc)

# Post-build step to create the .s19 file
# Corresponds to the objcopy call in common_arm/Makefile.common
set(S19_FILE "${CMAKE_CURRENT_BINARY_DIR}/fullimage.s19")
add_custom_command(
    TARGET fullimage.elf POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -Osrec --srec-forceS3 --strip-debug --no-change-warnings --change-addresses -0x100000 --change-start 0 --change-section-address .bss+0 --change-section-address .data-0x100000 --change-section-address .commonarea+0 $<TARGET_FILE:fullimage.elf> ${S19_FILE}
    COMMENT "Generating fullimage.s19"
)