-- Tariff Group & Group Selector
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- This special table together with voiptariffsel makes possible
-- to arrange tariffs into groups and to apply groups to accounts.
-- As a result, during tariff matching, a group tariff 
-- has priority over a default tariff (without any group assigned)
CREATE SEQUENCE voiptariffgrp_id_seq CYCLE;
CREATE TABLE voiptariffgrp (
	id INT DEFAULT nextval('voiptariffgrp_id_seq'),
	-- greater the value, higher the priority during tariff matching
	priority INT NOT NULL DEFAULT 1,
	-- description (like 'Germany - 10% discount' or 'USA - Gold Tariff')
	description TEXT NOT NULL,
	
	PRIMARY KEY (id)
);

-- binding between an account and a tariff group
CREATE SEQUENCE voiptariffsel_id_seq CYCLE;
CREATE TABLE voiptariffsel (
	id INT DEFAULT nextval('voiptariffsel_id_seq'),
	-- tariff group identifier
	grpid INT NOT NULL,
	-- account the tariff group applies to
	accountid INT NOT NULL,
	
	PRIMARY KEY (id),
	UNIQUE (grpid, accountid),
	FOREIGN KEY (grpid) REFERENCES voiptariffgrp(id),
	FOREIGN KEY (accountid) REFERENCES voipaccount(id)
);
