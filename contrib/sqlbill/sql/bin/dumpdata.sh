#!/bin/bash
#
# This script extracts data from the database.
# Compressed dump is sent to stdout. Use restore.sh script to restore
# data from a generated dump file.
# IMPORTANT: This scripts dumps DATA ONLY. Schema is not saved, so in order
# to perform full database restoration, you need first to create the schema
# and then run restore.sh to fill it with data.
#
# Usage:
#   dumpdata > dump

DBUSER=gkradius
DBSERVER=localhost
DBEXTRAOPTS=
DUMPTYPE="-a -Fc -Z 9 -v"

pg_dump $DUMPTYPE -U $DBUSER -h $DBSERVER $DBEXTRAOPTS voipdb
