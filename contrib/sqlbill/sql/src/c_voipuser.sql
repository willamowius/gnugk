-- VoIP user (IP phone, gateway)
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
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
	-- clear text user password for RADIUS authentication
	chappassword TEXT NOT NULL,
	-- aliases (E.164) allowed for this H.323 ID
	-- should be a regular expression
	allowedaliases TEXT NOT NULL DEFAULT '$^',
	-- additional aliases that should be assigned for this user
	assignaliases TEXT NOT NULL DEFAULT '',
	-- if it isn't NULL, allow this user to login only from the given IP pool
	framedip INET,
	-- first name
	firstname TEXT DEFAULT '' NOT NULL,
	-- surname
	surname TEXT DEFAULT '' NOT NULL,
	
	PRIMARY KEY (id),
	UNIQUE (h323id),
	FOREIGN KEY (accountid) REFERENCES voipaccount(id)
);

-- an index for fast access to active users
CREATE UNIQUE INDEX voipuser_active_idx ON voipuser(h323id) WHERE NOT disabled;
