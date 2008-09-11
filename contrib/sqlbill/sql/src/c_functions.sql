-- Helper functions
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004-2005, Michal Zygmuntowicz
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
	SELECT INTO trf.id NULL;
	SELECT INTO dst.id NULL;
	IF e164 IS NULL THEN
		RETURN trf;
	END IF;
	-- first try to find an exact match
	SELECT INTO dst * FROM voiptariffdst
		WHERE exactmatch AND prefix = e164
		LIMIT 1;
	IF dst.id IS NOT NULL THEN
		-- check whether the destination is blocked or not
		IF NOT dst.active THEN
			RETURN trf;
		END IF;
		SELECT INTO trf T.id, T.dstid, T.grpid, T.price, T.currencysym,
				T.initialincrement, T.regularincrement, T.graceperiod, T.description, T.active
			FROM voiptariff T JOIN voiptariffgrp G ON T.grpid = G.id 
				JOIN voiptariffsel S ON G.id = S.grpid
			WHERE NOT T.terminating AND T.dstid = dst.id AND T.currencysym = curr
				AND S.accountid = accid
			ORDER BY G.priority DESC
			LIMIT 1;
		IF FOUND AND trf.id IS NOT NULL THEN
			IF NOT trf.active THEN
				SELECT INTO trf.id NULL;
			END IF;
			RETURN trf;
		END IF;
	
		SELECT INTO trf * FROM voiptariff 
			WHERE NOT terminating AND dstid = dst.id AND currencysym = curr
				AND grpid IS NULL AND active;
		RETURN trf;
	END IF;

	IF length(e164) > 0 THEN
		IF (ascii(e164) >= 48 AND ascii(e164) <= 57) OR ascii(e164) = 42 THEN
			SELECT INTO dst.id, dst.active, trf.id D.id, D.active, T.id
				FROM voiptariffdst D LEFT JOIN voiptariff T ON T.dstid = D.id
					LEFT JOIN voiptariffgrp G ON T.grpid = G.id 
					LEFT JOIN voiptariffsel S ON S.grpid = G.id
				WHERE NOT D.exactmatch AND (e164 LIKE (D.prefix || ''%'')) 
					AND NOT T.terminating AND T.currencysym = curr  
					AND (T.grpid IS NULL OR S.accountid = accid)
				ORDER BY length(D.prefix) DESC, COALESCE(G.priority,-2147483648) DESC
				LIMIT 1;
		ELSE
			SELECT INTO dst.id, dst.active, trf.id D.id, D.active, T.id 
				FROM voiptariffdst D JOIN voiptariff T ON T.dstid = D.id
					JOIN voiptariffgrp G ON T.grpid = G.id 
					JOIN voiptariffsel S ON S.grpid = G.id
				WHERE D.prefix = ''PC'' AND T.currencysym = curr 
					AND S.accountid = accid
				ORDER BY G.priority DESC
				LIMIT 1;
			IF trf.id IS NULL THEN
				SELECT INTO dst.id, dst.active, trf.id D.id, D.active, T.id 
					FROM voiptariffdst D LEFT JOIN voiptariff T ON T.dstid = D.id
					WHERE D.prefix = ''PC'' AND T.currencysym = curr AND T.grpid IS NULL
					LIMIT 1;
			END IF;
		END IF;
		IF trf.id IS NOT NULL THEN
			SELECT INTO trf * FROM voiptariff WHERE id = trf.id;
		END IF;
	END IF;
	-- no active destination found
	IF dst.id IS NULL OR trf.id IS NULL THEN
		SELECT INTO trf.id NULL;
		RETURN trf;
	END IF;

	IF NOT dst.active OR NOT trf.active THEN
		SELECT INTO trf.id NULL;
	END IF;
	
	RETURN trf;
END;
' LANGUAGE 'plpgsql' STABLE CALLED ON NULL INPUT SECURITY INVOKER;

-- This function tries to find a tariff with the longest prefix match
-- $1 - voiptariffdst identifier
-- $2 - account that the tariff should apply to
-- $3 - currency for the tariff
CREATE OR REPLACE FUNCTION match_terminating_tariff(INT, INT, TEXT)
	RETURNS voiptariff AS
'
DECLARE
	trf voiptariff%ROWTYPE;
	dst_id ALIAS FOR $1;
	acc_id ALIAS FOR $2;
	curr ALIAS FOR $3;
BEGIN
	SELECT INTO trf.id NULL;
	IF curr IS NULL OR dst_id IS NULL THEN
		RETURN trf;
	END IF;
	
	SELECT INTO trf T.id, T.dstid, T.grpid, T.price, T.currencysym,
			T.initialincrement, T.regularincrement, T.graceperiod, T.description, T.active
		FROM voiptariff T JOIN voiptariffgrp G ON T.grpid = G.id 
			JOIN voiptariffsel S ON G.id = S.grpid
		WHERE T.terminating AND T.dstid = dst_id AND T.currencysym = curr
			AND S.accountid = acc_id
		ORDER BY G.priority DESC
		LIMIT 1;
	IF FOUND AND trf.id IS NOT NULL THEN
		IF NOT trf.active THEN
			SELECT INTO trf.id NULL;
		END IF;
		RETURN trf;
	END IF;
	
	SELECT INTO trf * FROM voiptariff 
		WHERE terminating AND dstid = dst_id AND currencysym = curr AND grpid IS NULL AND active;
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
	IF userip IS NOT NULL THEN
		SELECT INTO userid id FROM voipuser
			WHERE NOT checkh323id AND framedip >>= userip AND NOT disabled;
	END IF;
	IF NOT FOUND OR userid IS NULL THEN
		SELECT INTO userid id FROM voipuser
			WHERE checkh323id AND h323id = userh323id AND NOT disabled;
	END IF;
	RETURN userid;
END;
' LANGUAGE 'plpgsql' STABLE CALLED ON NULL INPUT SECURITY INVOKER;

-- This function tries to find a terminating user account based on the specified
-- network address and/or H.323 identifier
-- $1 - H.323 user's identifier or an E.164 number called
-- $2 - whether the $1 is an H.323 Id or an E.164 number
-- $3 - user's IP address 
CREATE OR REPLACE FUNCTION match_terminating_user(TEXT, BOOLEAN, INET)
	RETURNS voipuser AS
'
DECLARE
	userh323id ALIAS FOR $1;
	h323idmatch ALIAS FOR $2;
	userip ALIAS FOR $3;
	user voipuser%ROWTYPE;
BEGIN
	user.id := NULL;
	IF h323idmatch THEN
		SELECT INTO user * FROM voipuser
			WHERE terminating AND h323id = userh323id AND NOT disabled;
	END IF;
	IF NOT FOUND OR user.id IS NULL THEN
		SELECT INTO user * FROM voipuser
			WHERE terminating AND framedip >>= userip AND NOT disabled;
	END IF;
	RETURN user;
END;
' LANGUAGE 'plpgsql' STABLE CALLED ON NULL INPUT SECURITY INVOKER;

-- Converts 'T'/'F' string into a boolean value
CREATE OR REPLACE FUNCTION get_bool(TEXT)
	RETURNS BOOLEAN AS
'
	SELECT CASE $1 WHEN ''T'' THEN TRUE ELSE FALSE END;
' LANGUAGE SQL IMMUTABLE CALLED ON NULL INPUT SECURITY INVOKER;
