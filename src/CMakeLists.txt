################################################################################
### Airown - Sources ###########################################################
################################################################################

# Includes
SET(AIROWN_CFLAGS_INT "-Wall -O2")
SET(AIROWN_CFLAGS_EXT "${GLIB_CFLAGS} ${LORCON_CFLAGS} ${LIBNET_CFLAGS}")

# Libraries
SET(AIROWN_LINK_INT "")
SET(AIROWN_LINK_EXT "${GLIB_LDFLAGS} ${LORCON_LDFLAGS} ${LIBNET_LDFLAGS}")

# Sources
FILE(GLOB AIROWN_SRC ${AIROWN_SRC_DIR}/*.c)

# Compile
ADD_EXECUTABLE(airown ${AIROWN_SRC})
ADD_TARGET_CFLAGS(airown "${AIROWN_CFLAGS_INT} ${AIROWN_CFLAGS_EXT}")
TARGET_LINK_LIBRARIES(airown ${AIROWN_LINK_INT} ${AIROWN_LINK_EXT})

# Install
INSTALL(TARGETS airown DESTINATION bin)

