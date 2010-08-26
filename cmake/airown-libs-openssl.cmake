################################################################################
### OpenSSL ####################################################################
################################################################################

IF (NOT OPENSSL_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for OpenSSL")

    # Find
    PKG_CHECK_MODULES(OPENSSL openssl)
    PRINT_LIBRARY_INFO("OPENSSL" OPENSSL_FOUND "${OPENSSL_CFLAGS}" "${OPENSSL_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(OPENSSL_CHECKED 1)

ENDIF (NOT OPENSSL_CHECKED)

