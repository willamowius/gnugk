\echo Reading destinations from file destinations.csv

CREATE TEMPORARY TABLE voiptariffdst_temp (
  active TEXT NOT NULL,
  destination TEXT NOT NULL,
  carrierpfx TEXT NOT NULL,
  dialpfx TEXT NOT NULL,
  finalpfx TEXT NOT NULL,
  exactmatch TEXT NOT NULL
);

\copy voiptariffdst_temp from 'destinations.csv' with delimiter '\t'

\echo Preprocessing destinations

UPDATE voiptariffdst_temp SET finalpfx = trim(finalpfx, '\'\r\n\t '),
	active = trim(active, '\'\r\n\t '), destination = trim(destination, '\'\r\n\t '),
	exactmatch = trim(exactmatch, '\'\r\n\t ');

DELETE FROM voiptariffdst_temp WHERE active NOT IN ('T', 'F');

\echo Reading pricing information from file pricing.csv

CREATE TEMPORARY TABLE voiptariff_temp (
  destination TEXT NOT NULL,
  grp TEXT,
  netprice TEXT NOT NULL,
  vat TEXT NOT NULL,
  price TEXT NOT NULL,
  currency TEXT NOT NULL,
  initialincrement TEXT NOT NULL,
  regularincrement TEXT NOT NULL,
  graceperiod TEXT NOT NULL,
  terminating TEXT NOT NULL
);

\copy voiptariff_temp from 'pricing.csv' with delimiter '\t'

\echo Preprocessing pricing information

UPDATE voiptariff_temp SET destination = trim(destination, '\'\r\n\t '),
	grp = trim(grp, '\'\r\n\t '), price = trim(price, '\'\r\n\t '),
	currency = trim(currency, '\'\r\n\t '), initialincrement = trim(initialincrement, '\'\r\n\t '),
	regularincrement = trim(regularincrement, '\'\r\n\t '),
	graceperiod = trim(graceperiod, '\'\r\n\t '), terminating = trim(terminating, '\'\r\n\t ');

UPDATE voiptariff_temp SET price = replace(price, ',', '.');
UPDATE voiptariff_temp SET grp = '' WHERE grp IS NULL;

DELETE FROM voiptariff_temp WHERE (NOT initialincrement::TEXT ~* '[0-9]+') OR (NOT regularincrement::TEXT ~* '[0-9]+') OR (NOT graceperiod::TEXT ~* '[0-9]+');

CREATE TEMPORARY TABLE voiptarifffull_temp
(
  active TEXT NOT NULL,
  destination TEXT NOT NULL,
  prefix TEXT NOT NULL,
  exactmatch TEXT NOT NULL,
  grp TEXT,
  price TEXT NOT NULL,
  currency TEXT NOT NULL,
  initialincrement TEXT NOT NULL,
  regularincrement TEXT NOT NULL,
  graceperiod TEXT NOT NULL,
  terminating TEXT NOT NULL
);

INSERT INTO voiptarifffull_temp
	SELECT D.active, D.destination, D.finalpfx, D.exactmatch, T.grp, T.price, 
		T.currency,	T.initialincrement, T.regularincrement, T.graceperiod, T.terminating
	FROM voiptariffdst_temp D JOIN voiptariff_temp T ON D.destination = T.destination;

CREATE OR REPLACE FUNCTION update_tariffs(voiptarifffull_temp)
	RETURNS INT AS
'
DECLARE
	update_query TEXT;
	modified BOOLEAN := FALSE;
	execute_query BOOLEAN;
	dst RECORD;
	trf voiptariff%ROWTYPE;
	grp voiptariffgrp%ROWTYPE;
BEGIN
	-- find a destination associated with this tariff
	SELECT INTO dst * FROM voiptariffdst WHERE prefix = $1.prefix;
	IF NOT FOUND OR dst.id IS NULL THEN
		-- destination not found, create a new one
		INSERT INTO voiptariffdst (active, prefix, description, exactmatch)
			VALUES (get_bool($1.active), $1.prefix, $1.destination,
				get_bool($1.exactmatch));
		SELECT INTO dst * FROM voiptariffdst WHERE prefix = $1.prefix;
		IF NOT FOUND OR dst.id IS NULL THEN
			RAISE WARNING ''update_tariff: Could not insert a new destination: % %'', $1.prefix, $1.destination;
			RETURN -1;
		END IF;
		modified := TRUE;
	ELSE
		-- destination exists, update information if neccessary
		update_query := ''UPDATE voiptariffdst SET'';
		execute_query := FALSE;
		IF dst.description <> $1.destination THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' description = '' || quote_literal($1.destination);
			execute_query := TRUE;
		END IF;
		IF dst.active <> get_bool($1.active) THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' active = '' || $1.active;
			execute_query := TRUE;
		END IF;
		IF dst.exactmatch <> get_bool($1.exactmatch) THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' exactmatch = '' || $1.exactmatch;
			execute_query := TRUE;
		END IF;
		update_query := update_query || '' WHERE id = '' || CAST(dst.id AS TEXT);
		
		-- execute the query if at least one field needs to be updated
		IF execute_query THEN
			EXECUTE update_query;
			IF NOT FOUND THEN
				RAISE WARNING ''error:update_tariff: Failed to update destination info for prefix %'', $1.prefix;
				RETURN -1;
			END IF;
			modified := TRUE;
		END IF;
	END IF;

	-- try to find a tariff for the given destination
	IF length($1.grp) > 0 THEN
		-- this tariff belongs to some group
		SELECT INTO trf * FROM voiptariff T JOIN voiptariffgrp G
			ON T.grpid = G.id
			WHERE T.terminating = get_bool($1.terminating) 
				AND T.dstid = dst.id AND T.currencysym = $1.currency 
				AND G.description = $1.grp;
	ELSE
		-- this is a default tariff
		SELECT INTO trf * FROM voiptariff 
			WHERE terminating = get_bool($1.terminating) 
				AND dstid = dst.id AND currencysym = $1.currency AND grpid IS NULL;
	END IF;
	IF NOT FOUND OR trf.id IS NULL THEN
		-- create a new entry for this tariff
		IF length($1.grp) > 0 THEN
			-- create an entry for the tariff group, if neccessary
			SELECT INTO grp * FROM voiptariffgrp WHERE description = $1.grp;
			IF NOT FOUND OR grp.id IS NULL THEN
				INSERT INTO voiptariffgrp (description) VALUES ($1.grp);
				SELECT INTO grp * FROM voiptariffgrp WHERE id = currval(''voiptariffgrp_id_seq'');
			END IF;
			INSERT INTO voiptariff (dstid, grpid, price, currencysym, 
					initialincrement, regularincrement, graceperiod, terminating)
				VALUES (dst.id, grp.id, CAST($1.price AS NUMERIC), $1.currency, 
					$1.initialincrement::INT, $1.regularincrement::INT, 
					$1.graceperiod::INT, get_bool($1.terminating));
		ELSE
			-- create a default tariff
			INSERT INTO voiptariff (dstid, price, currencysym, initialincrement, 
					regularincrement, graceperiod, terminating)
				VALUES (dst.id, CAST($1.price AS NUMERIC), $1.currency, 
					$1.initialincrement::INT, $1.regularincrement::INT, 
					$1.graceperiod::INT, get_bool($1.terminating));
		END IF;
		IF NOT FOUND THEN
			RAISE WARNING ''update_tariff: Failed to insert a new tariff for the prefix %'',
				dst.prefix;
			RETURN -1;
		END IF;
		modified := TRUE;
	ELSE
		-- the tariff already exists, check if it needs to be updated
		update_query := ''UPDATE voiptariff SET'';
		execute_query := FALSE;
		IF trf.price <> $1.price::NUMERIC(12,4) THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' price = '' || $1.price;
			execute_query := TRUE;
		END IF;
		IF trf.currencysym <> $1.currency THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' currencysym = '' || quote_literal($1.currency);
			execute_query := TRUE;
		END IF;
		IF trf.initialincrement <> $1.initialincrement THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' initialincrement = '' || CAST($1.initialincrement AS TEXT);
			execute_query := TRUE;
		END IF;
		IF trf.regularincrement <> $1.regularincrement THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' regularincrement = '' || CAST($1.regularincrement AS TEXT);
			execute_query := TRUE;
		END IF;
		IF trf.graceperiod <> $1.graceperiod THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' graceperiod = '' || CAST($1.graceperiod AS TEXT);
			execute_query := TRUE;
		END IF;
		IF trf.terminating <> get_bool($1.terminating) THEN
			IF execute_query THEN
				update_query := update_query || '','';
			END IF;
			update_query := update_query || '' terminating = '' || $1.terminating;
			execute_query := TRUE;
		END IF;
		update_query := update_query || '' WHERE id = '' || CAST(trf.id AS TEXT);
		IF execute_query THEN
			EXECUTE update_query;
			IF NOT FOUND THEN
				RAISE WARNING ''update_tariff: Failed to update a tariff with id %'',trf.id;
				RETURN -1;
			END IF;
			modified := TRUE;
		END IF;
	END IF;
	
	IF modified THEN
		RETURN 1;
	ELSE
		RETURN 0;
	END IF;
END;
' LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION remove_unused_tariffs()
	RETURNS INT AS
'
DECLARE
	trfcursor CURSOR FOR SELECT T.id AS tid, T.currencysym AS tcurrsym, 
		D.prefix AS tprefix, T.grpid AS grpid, T.terminating AS terminating
		FROM voiptariff T JOIN voiptariffdst D ON T.dstid = D.id;
	trf RECORD;
	tfound BOOLEAN;
	numremoved INT := 0;
	grpname TEXT;
BEGIN
	OPEN trfcursor;
	LOOP
		FETCH trfcursor INTO trf;
		EXIT WHEN NOT FOUND;
		IF trf.grpid IS NOT NULL THEN
			SELECT INTO grpname description FROM voiptariffgrp WHERE id = trf.grpid;
		ELSE
			grpname := '''';
		END IF;
		tfound := NULL;
		SELECT INTO tfound TRUE FROM voiptarifffull_temp 
			WHERE prefix = trf.tprefix AND currency = trf.tcurrsym
				AND grp = grpname AND trf.terminating = get_bool(terminating);
		IF NOT FOUND OR tfound IS NULL THEN
			RAISE INFO ''Removing tariff for %, %, %'', trf.tprefix, trf.tcurrsym, grpname;
			DELETE FROM voiptariff WHERE id = trf.tid;
			IF FOUND THEN
				numremoved := numremoved + 1;
			END IF;
		END IF;
	END LOOP;
	CLOSE trfcursor;
	RETURN numremoved;
END;
' LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION remove_unused_destinations() RETURNS INT AS
'
DECLARE
	dstcursor CURSOR FOR SELECT id, prefix, description FROM voiptariffdst;
	dst RECORD;
	dstfound BOOLEAN;
	numremoved INT := 0;
BEGIN
	OPEN dstcursor;
	LOOP
		FETCH dstcursor INTO dst;
		EXIT WHEN NOT FOUND;
		dstfound := NULL;
		SELECT INTO dstfound TRUE FROM voiptarifffull_temp WHERE prefix = dst.prefix;
		IF NOT FOUND OR dstfound IS NULL THEN
			RAISE INFO ''Removing destination % - %'', dst.description, dst.prefix;
			DELETE FROM voiptariffdst WHERE id = dst.id;
			IF FOUND THEN
				numremoved := numremoved + 1;
			END IF;
		END IF;
	END LOOP;
	CLOSE dstcursor;
	RETURN numremoved;
END;
' LANGUAGE 'plpgsql';

\echo Updating tariffs

SELECT SUM(update_tariffs(voiptarifffull_temp)) AS tariffs_updated FROM voiptarifffull_temp;
SELECT remove_unused_tariffs() AS tariffs_removed;
SELECT remove_unused_destinations() AS destinations_removed;

\echo Cleanup

DROP FUNCTION remove_unused_tariffs();
DROP FUNCTION remove_unused_destinations();
DROP FUNCTION update_tariffs(voiptarifffull_temp);
DROP TABLE voiptariffdst_temp;
DROP TABLE voiptariff_temp;
DROP TABLE voiptarifffull_temp;
