find_path(MYSQL_INCLUDE_DIR mysql.h PATHS /usr/local/include/mysql /usr/include/mysql)
find_library(MYSQL_LIBRARY NAME mysqlclient PATH_SUFFIXES lib64 lib PATHS /usr/local /usr)

#message(STATUS "${MYSQL_INCLUDE_DIR} ${MYSQL_LIBRARY}")
if (MYSQL_INCLUDE_DIR AND MYSQL_LIBRARY)
	set(MYSQL_FOUND 1)
endif ()

