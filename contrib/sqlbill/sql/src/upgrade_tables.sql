BEGIN;

CREATE OR REPLACE FUNCTION upgrade_db() RETURNS BOOLEAN AS
'
DECLARE
	s TEXT;
	majorver INT := 1;
	minorver INT := 0;
	buildno INT := 1;
	dbmajorver INT;
	dbminorver INT;
	dbbuildno INT;
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
		OR (dbmajorver = majorver AND dbminorver = minorver AND dbbuildno >= buildno) THEN
		RAISE WARNING ''Trying to upgrade the same or newer database version (%.%.% => %.%.%)'',
			dbmajorver, dbminorver, dbbuildno, majorver, minorver, buildno;
		RETURN FALSE;
	END IF;

	RAISE INFO ''Upgrading database version from %.%.% to %.%.%...'',
		dbmajorver, dbminorver, dbbuildno, majorver, minorver, buildno;
		
	UPDATE voipglobals SET majorversion = majorver, minorversion = minorver,
		buildnumber = buildno;
		
	RAISE INFO ''Upgrade complete'';
	RETURN TRUE;
END;
' LANGUAGE 'plpgsql' SECURITY INVOKER;

SELECT CASE upgrade_db() WHEN TRUE THEN 'Success' ELSE 'Failure' END AS Upgrade_result;
