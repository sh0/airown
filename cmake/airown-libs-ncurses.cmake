################################################################################
### NCURSES ####################################################################
################################################################################

IF (NOT NCURSES_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for NCURSES (libncurses)")

    # Find
    FIND_PATH(NCURSES_INCLUDE_DIR NAMES ncurses.h PATH_SUFFIXES ncurses)
    FIND_LIBRARY(NCURSES_LIBRARY NAMES ncurses)

    # Result
    IF (NCURSES_INCLUDE_DIR AND NCURSES_LIBRARY)
        SET(NCURSES_FOUND 1)
    ENDIF (NCURSES_INCLUDE_DIR AND NCURSES_LIBRARY)
    
    # Compiler
    SET(NCURSES_CFLAGS "-I${NCURSES_INCLUDE_DIR}")
    SET(NCURSES_LDFLAGS "${NCURSES_LIBRARY}")
    PRINT_LIBRARY_INFO("NCURSES" NCURSES_FOUND "${NCURSES_CFLAGS}" "${NCURSES_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(NCURSES_CHECKED 1)

ENDIF (NOT NCURSES_CHECKED)

