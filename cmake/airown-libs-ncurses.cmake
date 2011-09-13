################################################################################
### NCURSES ####################################################################
################################################################################

IF (NOT NCURSES_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for ncurses")

    # Find
    FIND_LIBRARY(CURSES_NCURSES_LIBRARY NAMES ncurses)
    
    GET_FILENAME_COMPONENT(_cursesLibDir "${CURSES_NCURSES_LIBRARY}" PATH)
    GET_FILENAME_COMPONENT(_cursesParentDir "${_cursesLibDir}" PATH)

    FIND_FILE(CURSES_HAVE_NCURSES_H         ncurses.h)
    FIND_FILE(CURSES_HAVE_NCURSES_NCURSES_H ncurses/ncurses.h)
    FIND_FILE(CURSES_HAVE_NCURSES_CURSES_H  ncurses/curses.h)

    FIND_PATH(CURSES_NCURSES_INCLUDE_PATH ncurses.h ncurses/ncurses.h  ncurses/curses.h)
    FIND_PATH(CURSES_NCURSES_INCLUDE_PATH curses.h  HINTS "${_cursesParentDir}/include")
    
    SET(NCURSES_FOUND CURSES_NCURSES_INCLUDE_PATH)
    SET(NCURSES_CFLAGS "-I${CURSES_NCURSES_INCLUDE_PATH}")
    SET(NCURSES_LDFLAGS "${CURSES_NCURSES_LIBRARY}")
    PRINT_LIBRARY_INFO("NCURSES" NCURSES_FOUND "${NCURSES_CFLAGS}" "${NCURSES_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(NCURSES_CHECKED 1)

ENDIF (NOT NCURSES_CHECKED)

