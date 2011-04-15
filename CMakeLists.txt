cmake_minimum_required(VERSION 2.6)

project(gnugk)

set(SOURCES singleton.cxx job.cxx yasocket.cxx h323util.cxx
           Toolkit.cxx SoftPBX.cxx GkStatus.cxx RasTbl.cxx Routing.cxx
           Neighbor.cxx GkClient.cxx gkauth.cxx RasSrv.cxx ProxyChannel.cxx
           gk.cxx version.cxx gkacct.cxx gktimer.cxx gkconfig.cxx
           sigmsg.cxx clirw.cxx cisco.cxx ipauth.cxx statusacct.cxx
           syslogacct.cxx capctrl.cxx MakeCall.cxx h460presence.cxx
		   gksql.cxx gksql_mysql.cxx gksql_pgsql.cxx gksql_sqlite.cxx gksql_firebird.cxx gksql_odbc.cxx)

add_executable(gnugk ${SOURCES})
add_definitions("-Os -fno-exceptions -felide-constructors -Wall -Wformat -Wformat-security -Wreorder")
add_definitions("-DPTRACING -D_REENTRANT -DNDEBUG -D_FORTIFY_SOURCE=2")
if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "64")
	add_definitions("-DP_64BIT")
endif()

# loom for FindXXX.cmake modules in our cmake folder
SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(PTLIB REQUIRED)
find_package(H323PLUS REQUIRED)
include_directories(${PTLIB_INCLUDE} ${H323PLUS_INCLUDE})
target_link_libraries(gnugk ${H323PLUS_LIBRARY} ${PTLIB_LIBRARY})
# TODO: check ptbuildopts.h to decide witch libs are needed ?
target_link_libraries(gnugk ssl expat pthread dl ldap rt)

option(HAS_H46018 "Enable H.460.18/.19 support" OFF)
option(HAS_H46023 "Enable H.460.23/.24 support" ON)
option(HAS_RADIUS "Enable Radius support" ON)
#option(LARGE_FDSET "Enable LARGE_FDSET support" 0)

if (${HAS_H46018} STREQUAL "ON")
	add_definitions("-DHAS_H46018=1")
endif()
if (${HAS_H46023} STREQUAL "ON")
	add_definitions("-DHAS_H46023=1")
endif()
if (${HAS_RADIUS} STREQUAL "ON")
	add_definitions("-DHAS_RADIUS=1")
endif()
# TODO: doesn't work, yet
if (${LARGE_FDSET})
	add_definitions("-DLARGE_FDSET=${LARGE_FDSET}")
else()
	set(LARGE_FDSET 0)
endif()

# databases
option(HAS_MYSQL "Enable MySQL support" OFF)
find_package(MYSQL)
if (MYSQL_FOUND)
	set(HAS_MYSQL ON)
	add_definitions("-DHAS_MYSQL=1")
	include_directories("${MYSQL_INCLUDE_DIR}")
	target_link_libraries(gnugk ${MYSQL_LIBRARY})
endif ()

option(HAS_PGSQL "Enable PostrgeSQL support" OFF)
find_package(POSTGRESQL)
if (POSTGRESQL_FOUND)
	set(HAS_PGSQL ON)
	add_definitions("-DHAS_PGSQL=1")
	include_directories("${POSTGRESQL_INCLUDE_DIR}")
	target_link_libraries(gnugk ${POSTGRESQL_LIBRARY} crypt)
endif ()

option(HAS_SQLITE "Enable Sqlite support" OFF)
find_package(SQLITE)
if (SQLITE_FOUND)
	set(HAS_SQLITE ON)
	add_definitions("-DHAS_SQLITE=1")
	include_directories("${SQLITE_INCLUDE_DIR}")
	target_link_libraries(gnugk ${SQLITE_LIBRARY})
endif ()

option(HAS_FIREBIRD "Enable Firebird support" OFF)
find_package(FIREBIRD)
if (FIREBIRD_FOUND)
	set(HAS_FIREBIRD ON)
	add_definitions("-DHAS_FIREBIRD=1")
	include_directories("${FIREBIRD_INCLUDE_DIR}")
	target_link_libraries(gnugk ${FIREBIRD_LIBRARY})
endif ()

option(HAS_ODBC "Enable ODBC support" OFF)
find_package(ODBC)
if (ODBC_FOUND)
	set(HAS_ODBC ON)
	add_definitions("-DHAS_ODBC=1")
	include_directories("${ODBC_INCLUDE_DIR}")
	target_link_libraries(gnugk ${ODBC_LIBRARY})
endif ()

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
message(STATUS "LARGE_FDSET = ${LARGE_FDSET}")
message(STATUS)
message(STATUS "Change the above values with: cmake -D<Variable>=<Value>")
message(STATUS)
message(STATUS "HAS_MYSQL = ${HAS_MYSQL}")
message(STATUS "HAS_PGSQL = ${HAS_PGSQL}")
message(STATUS "HAS_SQLITE = ${HAS_SQLITE}")
message(STATUS "HAS_FIREBIRD = ${HAS_FIREBIRD}")
message(STATUS "HAS_ODBC = ${HAS_ODBC}")
message(STATUS)
message(STATUS "You can now compile with 'make'")
message(STATUS "--------------------------------------------------")
message(STATUS)

