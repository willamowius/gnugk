#!/bin/bash
#
# This script extracts data from the database.
# Compressed dump is sent to stdout. Use restore.sh script to restore
# data from a generated dump file.
#
# Usage:
#   dumpdata > dump

echo "Dumping data from the database..."

DBUSER=gkradius
DBSERVER=localhost
DBEXTRAOPTS=
DUMPTYPE="-a -Fc -Z 9"

pg_dump $DUMPTYPE -U $DBUSER -h $DBSERVER $DBEXTRAOPTS voipdb
