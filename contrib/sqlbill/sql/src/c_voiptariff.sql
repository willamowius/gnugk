-- Tariff
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- tariff with a fixed price for a given prefix
CREATE SEQUENCE voiptariff_id_seq CYCLE;
CREATE TABLE voiptariff (
	id INT DEFAULT nextval('voiptariff_id_seq'),
	-- whether this destination (prefix) can be dialed
	active BOOLEAN NOT NULL DEFAULT TRUE,
	-- E.164 prefix or a special value 'PC' that specifies all
	-- non-E.164 (H.323 id) aliases starting with a letter, not digit
	prefix VARCHAR(8) NOT NULL,
	-- description (like country name)
	description TEXT NOT NULL,
	-- price
	price NUMERIC(8,3) NOT NULL,
	-- standard currency symbol for the price
	currencysym CHAR(3) NOT NULL DEFAULT 'USD',
	
	PRIMARY KEY (id),
	UNIQUE (prefix)
);

CREATE UNIQUE INDEX voiptariff_activepfx_idx ON voiptariff(prefix) WHERE active;
CREATE INDEX voiptariff_activecurrsym_idx ON voiptariff(currencysym) WHERE active;
CREATE INDEX voiptariff_activepc_idx ON voiptariff(prefix) WHERE prefix = 'PC' AND active;
CREATE INDEX voiptariff_activeasciipfx ON voiptariff(ascii(prefix)) WHERE active;
