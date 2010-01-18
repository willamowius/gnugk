find_path(SQLITE_INCLUDE_DIR sqlite3.h PATHS /usr/include/sqlite /usr/local/include /usr/local/include/sqlite)
find_library(SQLITE_LIBRARY NAME sqlite3 PATH_SUFFIXES lib64 lib PATHS /usr /usr/local)

#message(STATUS "${SQLITE_INCLUDE_DIR} ${SQLITE_LIBRARY}")
if (SQLITE_INCLUDE_DIR AND SQLITE_LIBRARY)
	set(SQLITE_FOUND 1)
endif ()

