################################################################################
### Libnet #####################################################################
################################################################################

IF (NOT LIBNET_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for LIBNET (libnet)")

    # Find
    FIND_PATH(LIBNET_INCLUDE_DIR NAMES libnet.h PATH_SUFFIXES libnet)
    FIND_LIBRARY(LIBNET_LIBRARY NAMES net)

    # Result
    IF (LIBNET_INCLUDE_DIR AND LIBNET_LIBRARY)
        SET(LIBNET_FOUND 1)
    ENDIF (LIBNET_INCLUDE_DIR AND LIBNET_LIBRARY)
    
    # Compiler
    SET(LIBNET_CFLAGS "-I${LIBNET_INCLUDE_DIR}")
    SET(LIBNET_LDFLAGS "${LIBNET_LIBRARY}")
    PRINT_LIBRARY_INFO("LIBNET" LIBNET_FOUND "${LIBNET_CFLAGS}" "${LIBNET_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(LIBNET_CHECKED 1)

ENDIF (NOT LIBNET_CHECKED)

