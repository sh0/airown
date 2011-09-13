################################################################################
### Lorcon #####################################################################
################################################################################

IF (NOT LORCON_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for LORCON (liborcon)")

    # Find
    FIND_PATH(LORCON_INCLUDE_DIR NAMES lorcon.h PATH_SUFFIXES lorcon lorcon2)
    FIND_LIBRARY(LORCON_LIBRARY NAMES orcon2)

    # Result
    IF (LORCON_INCLUDE_DIR AND LORCON_LIBRARY)
        SET(LORCON_FOUND 1)
    ENDIF (LORCON_INCLUDE_DIR AND LORCON_LIBRARY)
    
    # Compiler
    SET(LORCON_CFLAGS "-I${LORCON_INCLUDE_DIR}")
    SET(LORCON_LDFLAGS "${LORCON_LIBRARY}")
    PRINT_LIBRARY_INFO("LORCON" LORCON_FOUND "${LORCON_CFLAGS}" "${LORCON_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(LORCON_CHECKED 1)

ENDIF (NOT LORCON_CHECKED)

