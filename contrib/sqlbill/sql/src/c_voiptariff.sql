-- Tariff
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- tariff with a fixed price for a given destination
CREATE SEQUENCE voiptariff_id_seq CYCLE;
CREATE TABLE voiptariff (
	id INT DEFAULT nextval('voiptariff_id_seq'),
	-- tariff destination (prefix)
	dstid INT NOT NULL,
	-- group associated with this tariff (NULL if this is a default tariff)
	grpid INT DEFAULT NULL,
	-- price
	price NUMERIC(9,4) NOT NULL,
	-- standard currency symbol for the price
	currencysym CHAR(3) NOT NULL DEFAULT 'USD',
	-- first billing unit (seconds)
	initialincrement INT NOT NULL DEFAULT 60,
	-- regular (2dn, 3rd, ...) billing unit (seconds)
	-- if set to 0, call is free after initial increment
	regularincrement INT NOT NULL DEFAULT 60,
	-- call duration, below which the user will not be billed
	graceperiod INT NOT NULL DEFAULT 0,
	-- description
	description TEXT NOT NULL DEFAULT '',
	-- block a destination associated with this tariff
	active BOOLEAN NOT NULL DEFAULT TRUE,
	-- whether the tariff should apply to an originatin or terminating endpoint
	terminating BOOLEAN NOT NULL DEFAULT FALSE,
		
	CONSTRAINT voiptariff_pkey PRIMARY KEY (id),
	CONSTRAINT voiptariff_destination_exists FOREIGN KEY (dstid) REFERENCES voiptariffdst(id) ON UPDATE CASCADE,
	CONSTRAINT voiptariff_group_exists FOREIGN KEY (grpid) REFERENCES voiptariffgrp(id) ON UPDATE CASCADE,
	CONSTRAINT voiptariff_unique UNIQUE (dstid, grpid, currencysym, terminating),
	CONSTRAINT voiptariff_checkincrement CHECK (initialincrement > 0 AND regularincrement >= 0)
);

CREATE INDEX voiptariff_dstid_idx ON voiptariff(dstid);
