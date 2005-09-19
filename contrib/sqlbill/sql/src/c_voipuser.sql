-- VoIP user (IP phone, gateway)
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004-2005, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- H.323 endpoint (a gateway, ip phone, another gk)
CREATE SEQUENCE voipuser_id_seq;
CREATE TABLE voipuser (
	id INT DEFAULT nextval('voipuser_id_seq'),
	-- unique User-Name (h323_ID)
	h323id TEXT NOT NULL,
	-- voipaccount this user belongs to
	accountid INT NOT NULL,
	-- can be used to disable the user temporarily
	disabled BOOLEAN NOT NULL DEFAULT FALSE,
	-- authentication type for this user:
	--   TRUE - check username/password and/or framedip (if specified)
	--   FALSE - check framedip/password only, match user account based 
	--           on Framed-IP-Address
	checkh323id BOOLEAN NOT NULL DEFAULT TRUE,
	-- clear text user password for RADIUS authentication
	chappassword TEXT NOT NULL,
	-- aliases (E.164) allowed for this H.323 ID
	-- should be a regular expression (examples: '.*', '^(john|48581234567)$')
	allowedaliases TEXT NOT NULL DEFAULT '^$',
	-- additional aliases that should be assigned for this user
	assignaliases TEXT NOT NULL DEFAULT '',
	-- if it isn't NULL, allow this user to login only from the given IP pool
	framedip INET,
	-- whether this endpoint can terminate tariffic too
	terminating BOOLEAN DEFAULT FALSE NOT NULL,
	-- if not NULL, this user can access only the specified NAS
	nasaddress INET,

	CONSTRAINT voipuser_pkey PRIMARY KEY (id),
	CONSTRAINT voipuser_unique UNIQUE (h323id),
	CONSTRAINT voipuser_account_exists FOREIGN KEY (accountid) REFERENCES voipaccount(id)
);

-- an index for fast access to active users
CREATE UNIQUE INDEX voipuser_active_idx ON voipuser(h323id) WHERE checkh323id AND NOT disabled;
CREATE UNIQUE INDEX voipuser_framedip_idx ON voipuser(framedip) WHERE NOT checkh323id AND NOT disabled;
CREATE UNIQUE INDEX voipuser_terminatingh323id_idx ON voipuser(h323id) WHERE terminating;
CREATE UNIQUE INDEX voipuser_terminatingip_idx ON voipuser(framedip) WHERE terminating;
