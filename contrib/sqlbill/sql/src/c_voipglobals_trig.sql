-- Global settings for the billing system
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

CREATE OR REPLACE FUNCTION voipglobals_singleton_guard()
	RETURNS TRIGGER AS
'
DECLARE
	i INT := 0;
BEGIN
	SELECT INTO i COUNT(*) FROM voipglobals;
	IF i > 0 THEN
		RAISE WARNING ''sqlbill: cannot have more than one row in voipglobals table'';
		RETURN NULL;
	END IF;
	RETURN NEW;
END;
' LANGUAGE 'plpgsql' IMMUTABLE;

CREATE TRIGGER voipglobals_bi_trig BEFORE INSERT ON voipglobals
	FOR EACH ROW EXECUTE PROCEDURE voipglobals_singleton_guard();
