################################################################################
### Libnet #####################################################################
################################################################################

IF (NOT LIBNET_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for libnet")

    # Find
    #PKG_CHECK_MODULES(LIBNET libnet)
    SET(LIBNET_FOUND 1)
    SET(LIBNET_CFLAGS "")
    SET(LIBNET_LDFLAGS "-lnet")
    PRINT_LIBRARY_INFO("Libnet" LIBNET_FOUND "${LIBNET_CFLAGS}" "${LIBNET_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(LIBNET_CHECKED 1)

ENDIF (NOT LIBNET_CHECKED)

