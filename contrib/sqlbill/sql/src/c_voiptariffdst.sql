-- Tariff Destination
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- tariff destination (prefix)
CREATE SEQUENCE voiptariffdst_id_seq CYCLE;
CREATE TABLE voiptariffdst (
	id INT DEFAULT nextval('voiptariffdst_id_seq'),
	-- whether this destination (prefix) can be dialed
	active BOOLEAN NOT NULL DEFAULT TRUE,
	-- E.164 prefix or a special value 'PC' that specifies all
	-- non-E.164 (H.323 id) aliases starting with a letter, not digit
	prefix VARCHAR(12) NOT NULL,
	-- description (like country name)
	description TEXT NOT NULL,
	
	PRIMARY KEY (id),
	UNIQUE (prefix)
);

CREATE UNIQUE INDEX voiptariffdst_activepfx_idx ON voiptariffdst(prefix) WHERE active;
CREATE INDEX voiptariffdst_activepc_idx ON voiptariffdst(prefix) WHERE prefix = 'PC' AND active;
CREATE INDEX voiptariffdst_activeasciipfx ON voiptariffdst(ascii(prefix)) WHERE active;
