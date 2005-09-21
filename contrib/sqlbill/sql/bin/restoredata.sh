#!/bin/bash
#
# This script restores data from a previously generated database dump.
# The database should be empty (no data, only table definitions) prior
# to the restore operation. Use dumpdata.sh script to dump data to a file.
# IMPORTANT: The restore operation has to be executed as PostgreSQL superuser
# in order to be able to disable triggers.
#
# Usage:
#   restoredata < dump

DBUSER=postgres
DBSERVER=localhost
DBEXTRAOPTS=
DUMPTYPE="-a --disable-triggers -v"

pg_restore $DUMPTYPE -U $DBUSER -h $DBSERVER $DBEXTRAOPTS -d voipdb
