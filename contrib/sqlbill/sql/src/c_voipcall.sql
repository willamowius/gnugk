-- Call Detail Record
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

CREATE SEQUENCE voipcall_id_seq CYCLE;
CREATE TABLE voipcall (
	-- BIGINT as there may be lots of calls
	id BIGINT DEFAULT nextval('voipcall_id_seq'),

	-- account that has been billed for this call (can be NULL)
	accountid INT,
    
	-- User-Name
	h323id TEXT NOT NULL,
  
	-- Acct-Session-Id attribute
	acctsessionid TEXT NOT NULL,
	-- H.323 Conference Identifier string
	h323confid TEXT DEFAULT '' NOT NULL,

	-- IP address of the gatekeeper
	gkip INET NOT NULL,
	-- gatekeeper identifier (name)
	gkid TEXT DEFAULT '' NOT NULL,
  
	-- IP address of the calling party
	callingstationip INET DEFAULT '127.0.0.1'::INET NOT NULL,
	-- E.164 number or H.323 id of the calling party
	callingstationid TEXT DEFAULT '' NOT NULL,

	-- IP address of the called party
	calledstationip INET DEFAULT '127.0.0.1'::INET NOT NULL,  
	-- E.164 number or H.323 id of the called party
	calledstationid TEXT DEFAULT '' NOT NULL,

	-- timestamp for Q.931 Setup event
	setuptime TIMESTAMP(0) WITH TIME ZONE,  
	-- timestamp for Q.931 Connect event
	connecttime TIMESTAMP(0) WITH TIME ZONE,
	-- timestamp for Q.931 ReleaseComplete event
	disconnecttime TIMESTAMP(0) WITH TIME ZONE,
	-- Q.931 call termination cause
	terminatecause CHAR(2) DEFAULT '0' NOT NULL,
  
	-- call duration (seconds) - may be incrementally updated 
	-- while the call is in progress
	duration INT DEFAULT 0 NOT NULL,
	-- total call cost
	cost NUMERIC(12,4),
	-- price per minute
	price NUMERIC(9,4),
	-- standard currency symbol for cost and price
	currencysym CHAR(3),
	-- description for the matched tariff
	tariffdesc TEXT,
	-- the first billing unit (in seconds)
	initialincrement INT,
	-- remaining (2nd, 3rd, ...) billing units (in seconds)
	regularincrement INT,
	-- duration below which the user will not be billed
	graceperiod INT DEFAULT 0,
  
	-- Acct-Start event timestamp
	acctstarttime TIMESTAMP(0) WITH TIME ZONE NOT NULL,
	-- delay (seconds) for the acctstarttime
	acctstartdelay INT DEFAULT 0 NOT NULL,
	-- the most recent Acct-Update event timestamp
	acctupdatetime TIMESTAMP(0) WITH TIME ZONE NOT NULL,
	-- Acct-Stop event timestamp
	acctstoptime TIMESTAMP WITH TIME ZONE,
	-- delay (seconds) for the acctstoptime
	acctstopdelay INT DEFAULT 0 NOT NULL,

	-- voiptariffdst prefix that calledstationid has matched
	prefix TEXT DEFAULT '' NOT NULL,
	
	CONSTRAINT voipcall_pkey PRIMARY KEY(id),
	CONSTRAINT voipcall_account_exists FOREIGN KEY (accountid) REFERENCES voipaccount(id) ON UPDATE CASCADE
) WITHOUT OIDS;
-- we do not want PostgreSQL to generate OID for each call record

-- for fast call update
CREATE UNIQUE INDEX voipcall_acctupdatestop_idx ON voipcall(acctsessionid, gkip) WHERE acctstoptime IS NULL;
