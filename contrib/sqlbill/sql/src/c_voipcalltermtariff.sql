-- Termination tariff information for voipcall
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- tariff with a fixed price for a given destination
CREATE SEQUENCE voipcalltermtariff_id_seq CYCLE;
CREATE TABLE voipcalltermtariff (
	id INT DEFAULT nextval('voipcalltermtariff_id_seq'),
	-- call associated with this termination tariff
	callid INT NOT NULL,
	-- terminating account
	accountid INT NOT NULL,
	-- terminating voipuser
	h323id TEXT NOT NULL,
	-- terminating IP
	terminatingip INET,
	-- total call cost
	cost NUMERIC(12,4),
	-- price
	price NUMERIC(9,4) NOT NULL,
	-- standard currency symbol for the price
	currencysym CHAR(3) NOT NULL DEFAULT 'USD',
	-- first billing unit (seconds)
	initialincrement INT NOT NULL DEFAULT 60,
	-- regular (2dn, 3rd, ...) billing unit (seconds)
	regularincrement INT NOT NULL DEFAULT 60,
	-- call duration, below which the user will not be billed
	graceperiod INT NOT NULL DEFAULT 0,
	-- description
	tariffdesc TEXT NOT NULL DEFAULT '',
		
	CONSTRAINT voipcalltermtariff_pkey PRIMARY KEY (id),
	CONSTRAINT voipcalltermtariff_call_exists FOREIGN KEY (callid) REFERENCES voipcall(id) ON UPDATE CASCADE ON DELETE CASCADE,
	CONSTRAINT voipcalltermtariff_account_exists FOREIGN KEY (accountid) REFERENCES voipaccount(id) ON UPDATE CASCADE
);
