find_path(POSTGRESQL_INCLUDE_DIR libpq-fe.h PATHS /usr/include/pgsql /usr/local/include /usr/local/include/pgsql /usr/local/pgsql/include)
find_library(POSTGRESQL_LIBRARY NAME pq PATH_SUFFIXES lib64 lib PATHS /usr /usr/local /usr/local/pgsql)

#message(STATUS "${POSTGRESQL_INCLUDE_DIR} ${POSTGRESQL_LIBRARY}")
if (POSTGRESQL_INCLUDE_DIR AND POSTGRESQL_LIBRARY)
	set(POSTGRESQL_FOUND 1)
endif ()

