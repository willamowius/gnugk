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
	regularincrement INT NOT NULL DEFAULT 60,
	-- description
	description TEXT NOT NULL DEFAULT '',
	
	PRIMARY KEY (id),
	FOREIGN KEY (dstid) REFERENCES voiptariffdst(id),
	FOREIGN KEY (grpid) REFERENCES voiptariffgrp(id),
	UNIQUE (dstid, grpid, currencysym)
);

CREATE INDEX voiptariff_dstid_idx ON voiptariff(dstid);
