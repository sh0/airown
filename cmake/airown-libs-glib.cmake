################################################################################
### GLib #######################################################################
################################################################################

IF (NOT GLIB_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for GLIB (glib-2.0, gthread-2.0)")

    # Find
	PKG_CHECK_MODULES(GLIB glib-2.0 gthread-2.0)
	PRINT_LIBRARY_INFO("GLIB" GLIB_FOUND "${GLIB_CFLAGS}" "${GLIB_LDFLAGS}")

    # Set as checked
	SET(GLIB_CHECKED 1)

ENDIF (NOT GLIB_CHECKED)

