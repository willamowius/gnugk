#!/bin/bash
#
# This script restores data from a previously generated database dump.
# The database should be empty (no data, only table definitions) prior
# to the restore operation. Use dumpdata.sh script to dump data to a file.
#
# Usage:
#   restoredata < dump

echo "Restoring data from the database dump..."

DBUSER=gkradius
DBSUPERUSER=postgres
DBSERVER=localhost
DBEXTRAOPTS=
DUMPTYPE="-a --disable-triggers"

pg_restore $DUMPTYPE -S $DBSUPERUSER -U $DBUSER -h $DBSERVER $DBEXTRAOPTS -d voipdb
