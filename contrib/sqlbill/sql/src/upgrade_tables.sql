CREATE OR REPLACE FUNCTION upgrade_db() RETURNS BOOLEAN AS
'
DECLARE
	s TEXT;
	majorver INT := 1;
	minorver INT := 0;
	buildno INT := 2;
	dbmajorver INT;
	dbminorver INT;
	dbbuildno INT;
	attrfound INT;
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
	
	-- check for voipuser.termgateway column presence
	SELECT INTO attrfound COUNT(*) FROM pg_class C JOIN pg_attribute A ON a.attrelid = C.oid
		WHERE c.relname = ''voipuser'' AND A.attname = ''terminating'';
	IF attrfound = 0 THEN
		ALTER TABLE voipuser ADD COLUMN terminating BOOLEAN;
		UPDATE voipuser SET terminating = FALSE;
		ALTER TABLE voipuser ALTER COLUMN terminating SET DEFAULT FALSE;
		ALTER TABLE voipuser ALTER COLUMN terminating SET NOT NULL;
	END IF;

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

	RAISE INFO ''Upgrade complete'';
	RETURN TRUE;
END;
' LANGUAGE 'plpgsql' SECURITY INVOKER;

SELECT CASE upgrade_db() WHEN TRUE THEN 'Success' ELSE 'Failure' END AS Upgrade_result;
