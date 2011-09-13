################################################################################
### Netlink ####################################################################
################################################################################

IF (NOT NETLINK_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for NETLINK (libnl-1)")

    # Find
	PKG_CHECK_MODULES(NETLINK libnl-1)
	PRINT_LIBRARY_INFO("NETLINK" NETLINK_FOUND "${NETLINK_CFLAGS}" "${NETLINK_LDFLAGS}")

    # Set as checked
	SET(NETLINK_CHECKED 1)

ENDIF (NOT NETLINK_CHECKED)

