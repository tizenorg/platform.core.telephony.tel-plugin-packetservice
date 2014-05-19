CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(ps-plugin C)

#INCLUDE(FindPkgConfig)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(DATAROOTDIR "\${prefix}/share")
if(NOT DEFINED SYSCONFDIR)
	SET(SYSCONFDIR "/etc")
endif()

# Set required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED glib-2.0 gio-2.0 gio-unix-2.0 tcore tel-headers libtzplatform-config iniparser)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include/ ${CMAKE_SOURCE_DIR}/cmake_tmp )

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra -fvisibility=hidden -fPIC")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wmissing-declarations -Wcast-align")

### Purge unused code ###
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdata-sections -ffunction-sections -Wl,--gc-sections")

ADD_DEFINITIONS("-DFEATURE_TLOG_DEBUG")
ADD_DEFINITIONS("-DTCORE_LOG_TAG=\"PS\"")
ADD_DEFINITIONS("-DPLUGIN_VERSION=${VERSION}")
ADD_DEFINITIONS("-DEXPORT_API=__attribute__((visibility(\"default\")))")

MESSAGE(${CMAKE_C_FLAGS})
MESSAGE(${pkgs_LDFLAGS})

SET(SRCS
	src/main.c
	src/master.c
	src/modem.c
	src/service.c
	src/context.c
	src/tcore-interface.c
)

SET(INTROSPECTION_PATH ${CMAKE_SOURCE_DIR}/introspection)

ADD_CUSTOM_COMMAND(
	OUTPUT ${CMAKE_BINARY_DIR}/generated-code.c
	COMMAND gdbus-codegen --interface-prefix com.tcore.ps.
	--generate-c-code generated-code
	--c-namespace PacketService
	--c-generate-object-manager
	--generate-docbook generated-docs
	${INTROSPECTION_PATH}/master.xml
	${INTROSPECTION_PATH}/modem.xml
	${INTROSPECTION_PATH}/service.xml
	${INTROSPECTION_PATH}/context.xml
	COMMENT "Generating GDBus .c/.h"
)

# library build
ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRCS} ${CMAKE_BINARY_DIR}/generated-code.c)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES PREFIX "" OUTPUT_NAME ${PROJECT_NAME})

# install
INSTALL(FILES ${CMAKE_SOURCE_DIR}/src/ps-plugin.conf DESTINATION ${SYSCONFDIR}/dbus-1/system.d)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/resources/dnet_db.sql DESTINATION ${DATAROOTDIR}/ps-plugin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/resources/dnet_db_data.sql DESTINATION ${DATAROOTDIR}/ps-plugin)
INSTALL(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${LIB_INSTALL_DIR}/telephony/plugins)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION /usr/share/license RENAME tel-plugin-packetservice)
