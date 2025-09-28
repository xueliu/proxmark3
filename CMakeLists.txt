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

cmake_minimum_required(VERSION 3.13)

# Set the project name and languages
project(proxmark3 C CXX ASM)

# Set the path to the CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Platform selection
set(PLATFORM "PM3RDV4" CACHE STRING "Select the target platform")
set_property(CACHE PLATFORM PROPERTY STRINGS "PM3RDV4" "PM3GENERIC" "PM3ICOPYX" "PM3ULTIMATE")
message(STATUS "Platform: ${PLATFORM}")

# Platform extras
option(PLATFORM_EXTRAS_BTADDON "Enable BTADDON" OFF)
option(PLATFORM_EXTRAS_FLASH "Enable FLASH" OFF)
option(PLATFORM_EXTRAS_SMARTCARD "Enable SMARTCARD" OFF)
option(PLATFORM_EXTRAS_FPC_USART_DEV "Enable FPC_USART_DEV" OFF)

# Add the armsrc directory
add_subdirectory(armsrc)