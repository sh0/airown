################################################################################
### Lorcon #####################################################################
################################################################################

IF (NOT LORCON_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for LORCON")

    # Find
    #PKG_CHECK_MODULES(LORCON lorcon)
    SET(LORCON_FOUND 1)
    SET(LORCON_CFLAGS "-I/usr/include/lorcon2")
    SET(LORCON_LDFLAGS "-lorcon2")
    PRINT_LIBRARY_INFO("LORCON" LORCON_FOUND "${LORCON_CFLAGS}" "${LORCON_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(LORCON_CHECKED 1)

ENDIF (NOT LORCON_CHECKED)

