-- Database creation
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- for access from FreeRADIUS server
CREATE USER gkradius WITH ENCRYPTED PASSWORD 'gkradius' NOCREATEDB NOCREATEUSER;
-- create the database
CREATE DATABASE voipdb WITH OWNER gkradius;
