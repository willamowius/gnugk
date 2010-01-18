find_path(FIREBIRD_INCLUDE_DIR ibase.h PATHS /usr/include/firebird /usr/local/include /usr/local/include/firebird /usr/local/firebird/include)
find_library(FIREBIRD_LIBRARY NAME fbclient PATH_SUFFIXES lib64 lib PATHS /usr /usr/local /usr/local/firebird)

#message(STATUS "${FIREBIRD_INCLUDE_DIR} ${FIREBIRD_LIBRARY}")
if (FIREBIRD_INCLUDE_DIR AND FIREBIRD_LIBRARY)
	set(FIREBIRD_FOUND 1)
endif ()

