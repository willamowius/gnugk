-- Billing Account 
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- voip account for a single customer
-- it may associate with more than one voipuser
CREATE SEQUENCE voipaccount_id_seq;
CREATE TABLE voipaccount (
	id INT DEFAULT nextval('voipaccount_id_seq'),
	-- date when the account has been created
	created TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT now(),
	-- date when the account has been close (or NULL if it is active)
	closed TIMESTAMP(0) WITH TIME ZONE,
	-- can be use to disable the account temporarily 
	disabled BOOLEAN NOT NULL DEFAULT FALSE,
	-- current balance
	balance NUMERIC(12,4) NOT NULL DEFAULT 0,
	-- minimal allowed balance: 
	--   negative values are for postpaid accounts,
	--   0 is for prepaid,
	--   positive forces some minimal account balance to be kept
	balancelimit NUMERIC(12,4) NOT NULL DEFAULT 0,
	-- standard currency symbol for balance and balancelimit fields
	currencysym CHAR(3) NOT NULL DEFAULT 'USD',
	
	CONSTRAINT voipaccount_pkey PRIMARY KEY (id)
);

-- an index for fast access to all active and not disabled accounts
CREATE UNIQUE INDEX voipaccount_active_idx ON voipaccount(id) 
	WHERE closed IS NULL AND NOT disabled;
