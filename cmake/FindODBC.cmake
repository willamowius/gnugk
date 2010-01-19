find_path(ODBC_INCLUDE_DIR sqlext.h PATHS /usr/include/unixodbc /usr/local/include /usr/local/include/unixodbc /usr/local/unixodbc/include)
find_library(ODBC_LIBRARY NAME odbc PATH_SUFFIXES lib64 lib PATHS /usr /usr/lib/unixodbc /usr/lib64/unixodbc /usr/local /usr/local/lib/unixodbc /usr/local/lib64/unixodbc /usr/local/unixodbc)

#message(STATUS "${ODBC_INCLUDE_DIR} ${ODBC_LIBRARY}")
if (ODBC_INCLUDE_DIR AND ODBC_LIBRARY)
	set(ODBC_FOUND 1)
endif ()

