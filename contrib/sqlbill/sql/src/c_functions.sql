-- Helper functions
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- This function translates '=XX' ASCII escape sequences
-- back to ASCI characters
-- This is required because FreeRADIUS escapes strings before
-- passing them to the SQL backend
CREATE OR REPLACE FUNCTION radius_xlat(TEXT)
	RETURNS TEXT AS
'
DECLARE
	input_str TEXT;
	xlated_str TEXT;
	hex_str TEXT;
	eq_pos INT;
	hexcode INT;
BEGIN
	input_str := $1;
	xlated_str := '''';
	LOOP
		-- find =XX escape
		hex_str := substring(input_str from ''=[0-9A-Fa-f][0-9A-Fa-f]'');
		EXIT WHEN hex_str IS NULL OR input_str = '''';
		IF length(hex_str) < 1 THEN
			eq_pos := 0;
		ELSE
			eq_pos := position(hex_str in input_str);
		END IF;
		EXIT WHEN eq_pos = 0;
		-- append to the result substring preceeding =XX
		xlated_str := xlated_str || substring(input_str from 1 for (eq_pos-1));
		-- remove the processed substring from the input string
		input_str := substring(input_str from eq_pos + 3);
		-- convert hex to integer
		hex_str := lower(hex_str);
		eq_pos := ascii(substring(hex_str from 2 for 1));
		IF eq_pos > ascii(''9'') THEN
			eq_pos := eq_pos - ascii(''a'') + 10;
		ELSE
			eq_pos := eq_pos - ascii(''0'');
		END IF;
		hexcode := eq_pos * 16;
		eq_pos := ascii(substring(hex_str from 3 for 1));
		IF eq_pos > ascii(''9'') THEN
			eq_pos := eq_pos - ascii(''a'') + 10;
		ELSE
			eq_pos := eq_pos - ascii(''0'');
		END IF;
		hexcode := hexcode + eq_pos;
		-- append ASCII char to the result
		xlated_str := xlated_str || chr(hexcode);
	END LOOP;
	-- append any remaining characters to the result
	xlated_str := xlated_str || input_str;
	RETURN xlated_str;
END;
' LANGUAGE 'plpgsql' IMMUTABLE RETURNS NULL ON NULL INPUT SECURITY INVOKER;


-- This function tries to find a tariff with the longest prefix match
-- $1 - E.164 number to match
-- $2 - account that the tariff should apply to
-- $3 - currency for the tariff
CREATE OR REPLACE FUNCTION match_tariff(TEXT, INT, TEXT)
	RETURNS voiptariff AS
'
DECLARE
	trf voiptariff%ROWTYPE;
	dst voiptariffdst%ROWTYPE;
	e164 ALIAS FOR $1;
	accid ALIAS FOR $2;
	curr ALIAS FOR $3;
BEGIN
	SELECT INTO trf NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL;
	SELECT INTO dst NULL, NULL, NULL, NULL;
	IF e164 IS NULL THEN
		RETURN trf;
	END IF;
	-- find an active destination for the given e164 (longest prefix match)
	IF length(e164) > 0 THEN
		IF ascii(e164) >= 48 AND ascii(e164) <= 57 THEN
			SELECT INTO dst * FROM voiptariffdst
				WHERE active AND ascii(prefix) = ascii(e164)
					AND (e164 LIKE (prefix || ''%''))
				ORDER BY length(prefix) DESC
				LIMIT 1;
		ELSE
			SELECT INTO dst * FROM voiptariffdst
				WHERE active AND prefix = ''PC''
				ORDER BY length(prefix) DESC
				LIMIT 1;
		END IF;
	END IF;
	-- no active destination found
	IF dst.id IS NULL THEN
		RETURN trf;
	END IF;

	SELECT INTO trf T.id, T.dstid, T.grpid, T.price, T.currencysym,
			T.initialincrement, T.regularincrement, T.graceperiod, T.description, T.active
		FROM voiptariff T JOIN voiptariffgrp G ON T.grpid = G.id 
			JOIN voiptariffsel S ON G.id = S.grpid
		WHERE dstid = dst.id AND currencysym = curr	AND S.accountid = accid
		ORDER BY G.priority DESC
		LIMIT 1;
	IF FOUND AND trf.id IS NOT NULL THEN
		IF NOT trf.active THEN
			SELECT INTO trf NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL;
		END IF;
		RETURN trf;
	END IF;
	
	SELECT INTO trf * FROM voiptariff 
		WHERE dstid = dst.id AND currencysym = curr AND grpid IS NULL AND active;
	RETURN trf;
END;
' LANGUAGE 'plpgsql' STABLE CALLED ON NULL INPUT SECURITY INVOKER;

-- This function tries to find an user account based on the specified
-- network address and/or H.323 identifier
-- $1 - H.323 user's identifier to match
-- $2 - user's IP address 
CREATE OR REPLACE FUNCTION match_user(TEXT, INET)
	RETURNS INT AS
'
DECLARE
	userh323id ALIAS FOR $1;
	userip ALIAS FOR $2;
	userid INT := NULL;
BEGIN
	SELECT INTO userid id FROM voipuser
		WHERE NOT checkh323id AND framedip >>= userip AND NOT disabled;
	IF NOT FOUND OR userid IS NULL THEN
		SELECT INTO userid id FROM voipuser
			WHERE checkh323id AND h323id = userh323id AND NOT disabled;
	END IF;
	RETURN userid;
END;
' LANGUAGE 'plpgsql' STABLE CALLED ON NULL INPUT SECURITY INVOKER;
