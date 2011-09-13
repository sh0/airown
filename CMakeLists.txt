################################################################################
### Airown - CMake #############################################################
################################################################################

# CMake requirements
CMAKE_MINIMUM_REQUIRED(VERSION 2.6.2 FATAL_ERROR)

# Compat
IF (COMMAND cmake_policy)
    cmake_policy(SET CMP0004 OLD)
ENDIF (COMMAND cmake_policy)

# Paths
SET(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" "${CMAKE_MODULE_PATH}")
SET(AIROWN_SRC_DIR "${CMAKE_SOURCE_DIR}/src")

# Check build directory
IF (${CMAKE_SOURCE_DIR} MATCHES ${CMAKE_BINARY_DIR})
	MESSAGE("Please do an out-of-tree build:")
	MESSAGE("rm CMakeCache.txt; mkdir build; cd build; cmake ..; make")
	MESSAGE(FATAL_ERROR "in-tree-build detected")
ENDIF (${CMAKE_SOURCE_DIR} MATCHES ${CMAKE_BINARY_DIR})

# Project
PROJECT(airown)
SET(VERSION 20110913)

# Options
OPTION(VERBOSE "Verbose cmake output" OFF)

# Libraries
INCLUDE(airown-helpers)
INCLUDE(airown-libs-general)
INCLUDE(airown-libs-glib)
INCLUDE(airown-libs-openssl)
INCLUDE(airown-libs-lorcon)
INCLUDE(airown-libs-libnet)
INCLUDE(airown-libs-ncurses)

# Config files
INCLUDE_DIRECTORIES("${CMAKE_BINARY_DIR}")
CONFIGURE_FILE(
  "${AIROWN_SRC_DIR}/ao_cmake.h.in"
  "${CMAKE_BINARY_DIR}/ao_cmake.h"
)

# Subdirs
ADD_SUBDIRECTORY(src)

