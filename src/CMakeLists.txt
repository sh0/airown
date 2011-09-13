################################################################################
### Airown - Sources ###########################################################
################################################################################

# Includes
SET(AIROWN_CFLAGS_INT "-Wall -O2 -g")
SET(AIROWN_CFLAGS_EXT "${GLIB_CFLAGS} ${OPENSSL_CFLAGS} ${PCAP_CFLAGS} ${LORCON_CFLAGS} ${NETLINK_CFLAGS} ${LIBNET_CFLAGS} ${NCURSES_CFLAGS}")

# Libraries
SET(AIROWN_LINK_INT "")
SET(AIROWN_LINK_EXT "${GLIB_LDFLAGS} ${OPENSSL_LDFLAGS} ${PCAP_LDFLAGS} ${LORCON_LDFLAGS} ${NETLINK_LDFLAGS} ${LIBNET_LDFLAGS} ${NCURSES_LDFLAGS}")

# Sources
FILE(GLOB AIROWN_SRC ${AIROWN_SRC_DIR}/*.cpp)

# Compile
ADD_EXECUTABLE(airown ${AIROWN_SRC})
ADD_TARGET_CFLAGS(airown "${AIROWN_CFLAGS_INT} ${AIROWN_CFLAGS_EXT}")
TARGET_LINK_LIBRARIES(airown ${AIROWN_LINK_INT} ${AIROWN_LINK_EXT})

# Install
INSTALL(TARGETS airown DESTINATION bin)

