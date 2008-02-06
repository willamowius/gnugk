-- Database upgrade scripts
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004-2005, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

CREATE OR REPLACE FUNCTION upgrade_db() RETURNS BOOLEAN AS
'
DECLARE
	s TEXT;
	majorver INT := 1;
	minorver INT := 0;
	buildno INT := 6;
	dbmajorver INT;
	dbminorver INT;
	dbbuildno INT;
	attrfound INT;
	constraintname TEXT;
	query TEXT;
BEGIN
	SELECT INTO s relname FROM pg_catalog.pg_class 
		WHERE relname = ''voipglobals'';
	IF s IS NULL THEN
		RAISE WARNING ''Upgrade is supported only for database version 1.0.1 or newer'';
		RETURN FALSE;
	END IF;
	
	SELECT INTO dbmajorver, dbminorver, dbbuildno majorversion, minorversion,
		buildnumber FROM voipglobals;
	IF NOT FOUND THEN
		RAISE EXCEPTION ''Unable to extract version information for the database - no rows in voipglobals table'';
		RETURN FALSE;
	END IF;
	
	IF dbmajorver > majorver OR (dbmajorver = majorver AND dbminorver > minorver)
		OR (dbmajorver = majorver AND dbminorver = minorver AND dbbuildno > buildno) THEN
		RAISE WARNING ''Trying to upgrade from a newer database version (%.%.% > %.%.%)'',
			dbmajorver, dbminorver, dbbuildno, majorver, minorver, buildno;
		RETURN FALSE;
	END IF;

	RAISE INFO ''Upgrading database version from %.%.% to %.%.%...'',
		dbmajorver, dbminorver, dbbuildno, majorver, minorver, buildno;
		
	UPDATE voipglobals SET majorversion = majorver, minorversion = minorver,
		buildnumber = buildno;

	-- check for voiptariffdst.exactmatch column presence
	SELECT INTO attrfound COUNT(*) FROM pg_class C JOIN pg_attribute A ON a.attrelid = C.oid
		WHERE c.relname = ''voiptariffdst'' AND A.attname = ''exactmatch'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariffdst ADD COLUMN exactmatch BOOLEAN;
		UPDATE voiptariffdst SET exactmatch = FALSE;
		ALTER TABLE voiptariffdst ALTER COLUMN exactmatch SET DEFAULT FALSE;
		ALTER TABLE voiptariffdst ALTER COLUMN exactmatch SET NOT NULL;
	END IF;

	-- adjucts indexes for voiptariffdst
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_activeasciipfx'';
	IF attrfound <> 0 THEN
		DROP INDEX voiptariffdst_activeasciipfx;
	END IF;


	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_activeh323id_idx'';
	IF attrfound = 0 THEN
		CREATE UNIQUE INDEX voiptariffdst_activeh323id_idx 
			ON voiptariffdst(prefix) WHERE active AND exactmatch;
	END IF;

	-- check for voiptariff.terminating column presence
	SELECT INTO attrfound COUNT(*) FROM pg_class C JOIN pg_attribute A ON a.attrelid = C.oid
		WHERE c.relname = ''voiptariff'' AND A.attname = ''terminating'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariff ADD COLUMN terminating BOOLEAN;
		UPDATE voiptariff SET terminating = FALSE;
		ALTER TABLE voiptariff ALTER COLUMN terminating SET DEFAULT FALSE;
		ALTER TABLE voiptariff ALTER COLUMN terminating SET NOT NULL;
	END IF;
	
	SELECT INTO attrfound COUNT(*) FROM pg_class WHERE relname = ''voipcalltermtariff'';
	IF attrfound = 0 THEN
		CREATE SEQUENCE voipcalltermtariff_id_seq CYCLE;
		CREATE TABLE voipcalltermtariff (
			id INT DEFAULT nextval(''voipcalltermtariff_id_seq''),
			callid INT NOT NULL,
			accountid INT NOT NULL,
			h323id TEXT NOT NULL,
			terminatingip INET,
			cost NUMERIC(12,4),
			price NUMERIC(9,4) NOT NULL,
			currencysym CHAR(3) NOT NULL DEFAULT ''USD'',
			initialincrement INT NOT NULL DEFAULT 60,
			regularincrement INT NOT NULL DEFAULT 60,
			graceperiod INT NOT NULL DEFAULT 0,
			tariffdesc TEXT NOT NULL DEFAULT '''',
		
			PRIMARY KEY (id),
			FOREIGN KEY (callid) REFERENCES voipcall(id) ON UPDATE CASCADE ON DELETE CASCADE,
			FOREIGN KEY (accountid) REFERENCES voipaccount(id) ON UPDATE CASCADE
		);
	END IF;
	
	-- check for voipuser.terminating column presence
	SELECT INTO attrfound COUNT(*) FROM pg_class C JOIN pg_attribute A ON a.attrelid = C.oid
		WHERE c.relname = ''voipuser'' AND A.attname = ''terminating'';
	IF attrfound = 0 THEN
		ALTER TABLE voipuser ADD COLUMN terminating BOOLEAN;
		UPDATE voipuser SET terminating = FALSE;
		ALTER TABLE voipuser ALTER COLUMN terminating SET DEFAULT FALSE;
		ALTER TABLE voipuser ALTER COLUMN terminating SET NOT NULL;
	END IF;

	-- check for voipuser.nasaddress column presence
	SELECT INTO attrfound COUNT(*) FROM pg_class C JOIN pg_attribute A ON a.attrelid = C.oid
		WHERE c.relname = ''voipuser'' AND A.attname = ''nasaddress'';
	IF attrfound = 0 THEN
		ALTER TABLE voipuser ADD COLUMN nasaddress INET;
	END IF;

	-- create any missing voipuser indexes
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voipuser_terminatingh323id_idx'';
	IF attrfound = 0 THEN
		CREATE UNIQUE INDEX voipuser_terminatingh323id_idx ON voipuser(h323id) 
			WHERE terminating;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voipuser_terminatingip_idx'';
	IF attrfound = 0 THEN
		CREATE UNIQUE INDEX voipuser_terminatingip_idx ON voipuser(framedip) 
			WHERE terminating;
	END IF;

	-- recreate voiptariff constraints
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariff_dstid_key'';
	IF attrfound <> 0 THEN
		ALTER TABLE voiptariff DROP CONSTRAINT voiptariff_dstid_key;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariff_unique'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariff ADD CONSTRAINT voiptariff_unique UNIQUE (dstid, grpid, currencysym, terminating);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariff_checkincrement'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariff ADD CONSTRAINT voiptariff_checkincrement CHECK (initialincrement > 0 AND regularincrement >= 0);
	END IF;

	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voiptariff''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voiptariffdst'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voiptariff DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariff_destination_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariff ADD CONSTRAINT voiptariff_destination_exists 
			FOREIGN KEY (dstid) REFERENCES voiptariffdst(id) ON UPDATE CASCADE;
	END IF;

	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voiptariff''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voiptariffgrp'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voiptariff DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariff_group_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariff ADD CONSTRAINT voiptariff_group_exists 
			FOREIGN KEY (grpid) REFERENCES voiptariffgrp(id) ON UPDATE CASCADE;
	END IF;
		
	-- recreate voiptariffdst constraints
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariffdst_prefix_key'';
	IF attrfound <> 0 THEN
		ALTER TABLE voiptariffdst DROP CONSTRAINT voiptariffdst_prefix_key;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariffdst_unique'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariffdst ADD CONSTRAINT voiptariffdst_unique UNIQUE (prefix);
	END IF;

	-- recreate voiptariffsel constraints
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariffsel_grpid_key'';
	IF attrfound <> 0 THEN
		ALTER TABLE voiptariffsel DROP CONSTRAINT voiptariffsel_grpid_key;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariffsel_unique'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariffsel ADD CONSTRAINT voiptariffsel_unique UNIQUE (grpid, accountid);
	END IF;
	
	-- recreate voipuser constraints
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voipuser_h323id_key'';
	IF attrfound <> 0 THEN
		ALTER TABLE voipuser DROP CONSTRAINT voipuser_h323id_key;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voipuser_unique'';
	IF attrfound = 0 THEN
		ALTER TABLE voipuser ADD CONSTRAINT voipuser_unique UNIQUE (h323id);
	END IF;

	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voipuser''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voipaccount'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voipuser DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voipuser_account_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voipuser ADD CONSTRAINT voipuser_account_exists 
			FOREIGN KEY (accountid) REFERENCES voipaccount(id) ON UPDATE CASCADE;
	END IF;

	-- recreate voipcall constraints
	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voipcall''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voipaccount'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voipcall DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voipcall_account_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voipcall ADD CONSTRAINT voipcall_account_exists 
			FOREIGN KEY (accountid) REFERENCES voipaccount(id) ON UPDATE CASCADE;
	END IF;

	-- adjust indexes for voipcall
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voipcall_h323id_idx'';
	IF attrfound <> 0 THEN
		DROP INDEX voipcall_h323id_idx;
	END IF;
	
	-- recreate voipcalltermtariff constraints
	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voipcalltermtariff''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voipaccount'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voipcalltermtariff DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voipcalltermtariff_account_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voipcalltermtariff ADD CONSTRAINT voipcalltermtariff_account_exists 
			FOREIGN KEY (accountid) REFERENCES voipaccount(id) ON UPDATE CASCADE;
	END IF;

	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voipcalltermtariff''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voipcall'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voipcalltermtariff DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voipcalltermtariff_call_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voipcalltermtariff ADD CONSTRAINT voipcalltermtariff_call_exists 
			FOREIGN KEY (callid) REFERENCES voipcall(id) ON UPDATE CASCADE ON DELETE CASCADE;
	END IF;

	-- recreate voiptariffsel constraints
	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voiptariffsel''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voiptariffgrp'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voiptariffsel DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariffsel_group_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariffsel ADD CONSTRAINT voiptariffsel_group_exists 
			FOREIGN KEY (grpid) REFERENCES voiptariffgrp(id) ON UPDATE CASCADE;
	END IF;

	constraintname := NULL;
	SELECT INTO constraintname CC.conname FROM (SELECT C.conname, C.confrelid FROM pg_constraint C 
		JOIN pg_type T ON C.conrelid = T.typrelid WHERE T.typname = ''voiptariffsel''
		AND C.contype = ''f'') AS CC JOIN pg_type TT ON CC.confrelid = TT.typrelid
		AND TT.typname = ''voipaccount'';
	IF constraintname IS NOT NULL THEN
		EXECUTE ''ALTER TABLE voiptariffsel DROP CONSTRAINT ''
			|| quote_ident(constraintname);
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_constraint WHERE conname = ''voiptariffsel_account_exists'';
	IF attrfound = 0 THEN
		ALTER TABLE voiptariffsel ADD CONSTRAINT voiptariffsel_account_exists 
			FOREIGN KEY (accountid) REFERENCES voipaccount(id) ON UPDATE CASCADE;
	END IF;

	-- check for voipcall.prefix column presence
	SELECT INTO attrfound COUNT(*) FROM pg_class C JOIN pg_attribute A ON a.attrelid = C.oid
		WHERE c.relname = ''voipcall'' AND A.attname = ''prefix'';
	IF attrfound = 0 THEN
		ALTER TABLE voipcall ADD COLUMN prefix TEXT;
		UPDATE voipcall SET prefix = '''';
		ALTER TABLE voipcall ALTER COLUMN prefix SET DEFAULT '''';
		ALTER TABLE voipcall ALTER COLUMN prefix SET NOT NULL;
	END IF;

	-- create/deelte new/old voiptariffdst indexes
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_activepfx_idx'';
	IF attrfound <> 0 THEN
		DROP INDEX voiptariffdst_activepfx_idx;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_pfx_idx'';
	IF attrfound = 0 THEN
		CREATE UNIQUE INDEX voiptariffdst_pfx_idx ON voiptariffdst(prefix);
	END IF;

	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_activeh323id_idx'';
	IF attrfound <> 0 THEN
		DROP INDEX voiptariffdst_activeh323id_idx;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_h323id_idx'';
	IF attrfound = 0 THEN
		CREATE UNIQUE INDEX voiptariffdst_h323id_idx ON voiptariffdst(prefix)
			WHERE exactmatch;
	END IF;

	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_activepc_idx'';
	IF attrfound <> 0 THEN
		DROP INDEX voiptariffdst_activepc_idx;
	END IF;
	SELECT INTO attrfound COUNT(*) FROM pg_indexes WHERE indexname = ''voiptariffdst_pc_idx'';
	IF attrfound = 0 THEN
		CREATE UNIQUE INDEX voiptariffdst_pc_idx ON voiptariffdst(prefix)
			WHERE prefix = ''PC'';
	END IF;

	RAISE INFO ''Upgrade complete'';
	RETURN TRUE;
END;
' LANGUAGE 'plpgsql' SECURITY INVOKER;

SELECT CASE upgrade_db() WHEN TRUE THEN 'Success' ELSE 'Failure' END AS Upgrade_result;
