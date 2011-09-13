################################################################################
### Pcap #######################################################################
################################################################################

IF (NOT PCAP_CHECKED)

    # Messages
    MESSAGE(STATUS "################################################")
    MESSAGE(STATUS "Checking for PCAP (libpcap)")

    # Find
    FIND_PATH(PCAP_INCLUDE_DIR NAMES pcap.h PATH_SUFFIXES pcap)
    FIND_LIBRARY(PCAP_LIBRARY NAMES pcap)

    # Result
    IF (PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        SET(PCAP_FOUND 1)
    ENDIF (PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    
    # Compiler
    SET(PCAP_CFLAGS "-I${PCAP_INCLUDE_DIR}")
    SET(PCAP_LDFLAGS "${PCAP_LIBRARY}")
    PRINT_LIBRARY_INFO("PCAP" PCAP_FOUND "${PCAP_CFLAGS}" "${PCAP_LDFLAGS}" FATAL_ERROR)

    # Set as checked
    SET(PCAP_CHECKED 1)

ENDIF (NOT PCAP_CHECKED)

