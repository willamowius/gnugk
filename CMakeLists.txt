cmake_minimum_required(VERSION 2.6)

project(gnugk)

set(SOURCES main.cxx singleton.cxx job.cxx yasocket.cxx h323util.cxx
           Toolkit.cxx SoftPBX.cxx GkStatus.cxx RasTbl.cxx Routing.cxx
           Neighbor.cxx GkClient.cxx gkauth.cxx RasSrv.cxx ProxyChannel.cxx
           gk.cxx version.cxx gkacct.cxx gktimer.cxx gkconfig.cxx
           sigmsg.cxx clirw.cxx cisco.cxx ipauth.cxx statusacct.cxx
           syslogacct.cxx capctrl.cxx MakeCall.cxx h460presence.cxx)

add_executable(gnugk ${SOURCES})
add_definitions("-Os -fno-exceptions -felide-constructors -Wall -Wformat -Wformat-security -Wreorder")
add_definitions("-DPTRACING -D_REENTRANT -DNDEBUG -D_FORTIFY_SOURCE=2")
if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "64")
	add_definitions("-DP_64BIT")
endif()

SET(CMAKE_MODULE_PATH ".")

find_package(PTLIB REQUIRED)
find_package(H323PLUS REQUIRED)
include_directories(${PTLIB_INCLUDE} ${H323PLUS_INCLUDE})
target_link_libraries(gnugk ${H323PLUS_LIBRARY} ${PTLIB_LIBRARY})
# TODO: check ptbuildopts.h to decide witch libs are needed ?
target_link_libraries(gnugk ssl expat pthread dl ldap rt)

option(HAS_H46018 "Enable H.460.18/.19 support" OFF)
option(HAS_H46023 "Enable H.460.23/.24 support" ON)
option(HAS_RADIUS "Enable Radius support" ON)

if (${HAS_H46018} STREQUAL "ON")
	add_definitions("-DHAS_H46018=1")
endif()
if (${HAS_H46023} STREQUAL "ON")
	add_definitions("-DHAS_H46023=1")
endif()
if (${HAS_RADIUS} STREQUAL "ON")
	add_definitions("-DHAS_RADIUS=1")
endif()

# only needed on Windows, must change #undef to #cmakedefine in gnugkbuildopts.h.in
#configure_file (
#  "${PROJECT_SOURCE_DIR}/gnugkbuildopts.h.in"
#  "${PROJECT_BINARY_DIR}/gnugkbuildopts.h"
#  )

# for gnugkbuildopts.h
include_directories("${PROJECT_BINARY_DIR}")

message(STATUS)
message(STATUS "--------------------------------------------------")
message(STATUS "Settings:")
message(STATUS "HAS_H46018 = ${HAS_H46018}")
message(STATUS "HAS_H46023 = ${HAS_H46023}")
message(STATUS "HAS_RADIUS = ${HAS_RADIUS}")
message(STATUS)
message(STATUS "Change a value with: cmake -D<Variable>=<Value>")
message(STATUS)
message(STATUS "You can now compile with 'make'")
message(STATUS "--------------------------------------------------")
message(STATUS)

