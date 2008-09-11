-- RADIUS ARQ/RRQ processing functions
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004-2005, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- single RADIUS attribute value pair
CREATE TABLE voipradattr (
	-- unused
	id INT,
	-- attribute name ('User-Name' for example)
	attrname TEXT,
	-- attribute value ('user1')
	attrvalue TEXT,
	-- operator ('==',':=','=',...) for the name-value pair
	attrop TEXT
);

-- Extract a specific variable from multiple Cisco-AVPair attributes
-- $1 - a string of all value pairs from RADIUS request (%Z)
-- $2 - Cisco-AVPair variable name
CREATE OR REPLACE FUNCTION radius_get_ciscoavpair(TEXT, TEXT)
	RETURNS TEXT AS
'
DECLARE
	vplist ALIAS FOR $1;
	varname ALIAS FOR $2;
	s TEXT;
	vpstring TEXT;
	vpnum INT := 1;
	sepindex INT;
BEGIN
	LOOP
		-- extract next attriubute = value pair
		vpstring := split_part(vplist, ''\n'', vpnum);
		EXIT WHEN vpstring IS NULL;
		EXIT WHEN length(vpstring) = 0;
		sepindex := position(''='' in vpstring);
		EXIT WHEN sepindex IS NULL;
		IF sepindex > 1 THEN
			-- get attribute name
			s := substring(vpstring from 1 for (sepindex-1));
			s := trim('' \t'' from s);
			IF s = ''Cisco-AVPair'' THEN
				-- get attribute value
				vpstring := substring(vpstring from (sepindex + 1));
				vpstring := trim('' \t"'' from vpstring);
				sepindex := position(''='' in vpstring);
				IF sepindex IS NOT NULL THEN
					IF sepindex > 1 THEN
						-- get variable name
						s := substring(vpstring from 1 for (sepindex-1));
						s := trim('' \t'' from s);
						IF s = varname THEN
							s := substring(vpstring from sepindex + 1);
							RETURN radius_xlat(trim('' \t'' from s));
						END IF;
					END IF;
				END IF;
			END IF;
		END IF;
		vpnum := vpnum + 1;
	END LOOP;
	RETURN NULL;
END;
' LANGUAGE 'plpgsql' IMMUTABLE SECURITY INVOKER;

-- Extract a specific variable from the h323-ivr-out string
-- $1 - variable:value pairs to parse (example: 'terminal-alias:123,456')
-- $2 - variable name to match (example: 'terminal-alias')
CREATE OR REPLACE FUNCTION radius_get_ciscovar(TEXT, TEXT)
	RETURNS TEXT AS
'
DECLARE
	vplist ALIAS FOR $1;
	varname ALIAS FOR $2;
	parsedval TEXT;
	idx INT;
BEGIN
	parsedval := substring(vplist from varname || '':[^;]*'');
	idx := strpos(parsedval, '':'');
	IF idx > 0 THEN
		parsedval := substring(parsedval, idx + 1);
		RETURN parsedval;
	END IF;
	RETURN NULL;
END;
' LANGUAGE 'plpgsql' IMMUTABLE SECURITY INVOKER;

-- build a list of RADIUS check attribute-value pairs for endpoint registration request
-- $1 - User-Name
-- $2 - Framed-IP-Address
-- $3 - NAS-IP-Address
-- $4 - newline separated list of all a=v pairs in the request
CREATE OR REPLACE FUNCTION radius_get_check_rrq_attrs(TEXT, INET, INET, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	nasipaddress ALIAS FOR $3;
	vplist ALIAS FOR $4;
	username TEXT;
	reject_attr voipradattr%ROWTYPE;
	check_attr voipradattr%ROWTYPE;
	query_result RECORD;
	userid INT;
	aliasnum INT;
	rrqalias TEXT;
	aliases TEXT;
BEGIN
	-- prepare Auth-Type := Reject avp, as it is referenced very often
	reject_attr.id := 0;
	reject_attr.attrname := ''Auth-Type'';
	reject_attr.attrvalue := ''Reject'';
	reject_attr.attrop := '':='';
	
	-- check input parameters
	IF $1 IS NULL OR nasipaddress IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- remove RADIUS escapes
	username := radius_xlat($1);

	RAISE LOG ''sqlbill: RRQ(username: %; IP: %)'', username, framed_ip;
	
	userid := match_user(username, framed_ip);
	IF userid IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
		
	-- get user information
	SELECT INTO query_result h323id, chappassword, allowedaliases, framedip, nasaddress
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id 
		WHERE a.closed IS NULL AND NOT a.disabled AND u.id = userid;
	IF NOT FOUND OR query_result.chappassword IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;

	-- check if the endpoint is allowed to access this NAS
	IF query_result.nasaddress IS NOT NULL THEN
		IF NOT (query_result.nasaddress >>= nasipaddress) THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
	END IF;
		
	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
		IF framed_ip IS NULL THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
		IF NOT (query_result.framedip >>= framed_ip) THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
	END IF;

	-- check the list of aliases being registered, if it is present
	aliases := radius_get_ciscoavpair(vplist, ''h323-ivr-out'');
	aliases := radius_get_ciscovar(aliases, ''terminal-alias'');
	IF aliases IS NOT NULL THEN
		aliasnum := 1;
		LOOP
			rrqalias := split_part(aliases, '','', aliasnum);
			EXIT WHEN length(rrqalias) = 0;
			aliasnum := aliasnum + 1;
			IF NOT rrqalias = query_result.h323id AND NOT rrqalias ~ query_result.allowedaliases THEN
				RETURN NEXT reject_attr;
				RETURN;
			END IF;
		END LOOP;			
	END IF;
	
	-- return User-Password check avp
	check_attr.id := 0;
	check_attr.attrname := ''User-Password'';
	check_attr.attrvalue := query_result.chappassword;
	check_attr.attrop := ''=='';
	RETURN NEXT check_attr;
	
	RETURN;	
END;
' LANGUAGE 'plpgsql' CALLED ON NULL INPUT SECURITY INVOKER;

-- build a list of RADIUS reply attribute-value pairs for endpoint registration request
-- $1 - User-Name
-- $2 - Framed-IP-Address
-- $3 - NAS-IP-Address
-- $4 - newline separated list of all a=v pairs in the request
CREATE OR REPLACE FUNCTION radius_get_reply_rrq_attrs(TEXT, INET, INET, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	nasipaddress ALIAS FOR $3;
	vplist ALIAS FOR $4;
	username TEXT;
	rcode_attr voipradattr%ROWTYPE;
	reply_attr voipradattr%ROWTYPE;
	attr_num INT := 1;
	userid INT;
	query_result RECORD;
	aliasnum INT;
	rrqalias TEXT;
	aliases TEXT;
BEGIN
	-- prepare h323-return-code avp, as it is referenced very often
	rcode_attr.id := attr_num;
	rcode_attr.attrname := ''h323-return-code'';
	rcode_attr.attrvalue := ''h323-return-code='';
	rcode_attr.attrop := ''='';
	attr_num := attr_num + 1;
	
	-- check input parameters
	IF $1 IS NULL OR nasipaddress IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''11'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- remove RADIUS escapes
	username := radius_xlat($1);

	userid := match_user(username, framed_ip);
	IF userid IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''1'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- get user information
	SELECT INTO query_result h323id, balance, currencysym, allowedaliases, 
			assignaliases, framedip, nasaddress
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id
		WHERE a.closed IS NULL AND NOT a.disabled AND u.id = userid;
	IF NOT FOUND OR query_result.balance IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''1'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- check if the endpoint is allowed to access this NAS
	IF query_result.nasaddress IS NOT NULL THEN
		IF NOT (query_result.nasaddress >>= nasipaddress) THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
	END IF;

	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
		IF framed_ip IS NULL THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
		IF NOT (query_result.framedip >>= framed_ip) THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
	END IF;
	
	-- check the list of aliases being registered, if it is present
	aliases := radius_get_ciscoavpair(vplist, ''h323-ivr-out'');
	aliases := radius_get_ciscovar(aliases, ''terminal-alias'');
	IF aliases IS NOT NULL THEN
		aliasnum := 1;
		LOOP
			rrqalias := split_part(aliases, '','', aliasnum);
			EXIT WHEN length(rrqalias) = 0;
			aliasnum := aliasnum + 1;
			IF NOT rrqalias = query_result.h323id AND NOT rrqalias ~ query_result.allowedaliases THEN
				rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
				RETURN NEXT rcode_attr;
				RETURN;
			END IF;
		END LOOP;			
	END IF;

	rcode_attr.attrvalue := rcode_attr.attrvalue || ''0'';
	RETURN NEXT rcode_attr;
	
	reply_attr.id := attr_num;
	reply_attr.attrname := ''h323-credit-amount'';
	reply_attr.attrvalue := ''h323-credit-amount='' 
		|| to_char(query_result.balance,''FM9999990.00'');
	reply_attr.attrop := ''='';
	RETURN NEXT reply_attr;
	attr_num := attr_num + 1;
	
	reply_attr.id := attr_num;
	reply_attr.attrname := ''h323-currency'';
	reply_attr.attrvalue := ''h323-currency='' || query_result.currencysym;
	reply_attr.attrop := ''='';
	RETURN NEXT reply_attr;
	attr_num := attr_num + 1;
	
	reply_attr.id := attr_num;
	reply_attr.attrname := ''h323-billing-model'';
	reply_attr.attrvalue := ''h323-billing-model=2'';
	reply_attr.attrop := ''='';
	RETURN NEXT reply_attr;
	attr_num := attr_num + 1;

	IF length(query_result.assignaliases) > 0 THEN
		reply_attr.id := attr_num;
		reply_attr.attrname := ''Cisco-AVPair'';
		reply_attr.attrvalue := ''h323-ivr-in=terminal-alias:'' 
			|| query_result.assignaliases || '';'';
		reply_attr.attrop := ''='';
		RETURN NEXT reply_attr;
		attr_num := attr_num + 1;
	END IF;
	
	RETURN;	
END;
' LANGUAGE 'plpgsql' CALLED ON NULL INPUT SECURITY INVOKER;

-- build a list of RADIUS check attribute-value pairs for endpoint call admission request
-- $1 - User-Name
-- $2 - Framed-IP-Address
-- $3 - NAS-IP-Address
-- $4 - TRUE - the call is being answered, FALSE - the call is originated
-- $5 - calling station id
-- $6 - called station id
CREATE OR REPLACE FUNCTION radius_get_check_arq_attrs(TEXT, INET, INET, BOOLEAN, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	nasipaddress ALIAS FOR $3;
	answer_call ALIAS FOR $4;
	username TEXT;
	calling_station_id TEXT;
	called_station_id TEXT;
	reject_attr voipradattr%ROWTYPE;
	check_attr voipradattr%ROWTYPE;
	query_result RECORD;
	trf voiptariff%ROWTYPE;
	userid INT;
BEGIN
	-- prepare Auth-Type := Reject avp, as it is referenced very often
	reject_attr.id := 0;
	reject_attr.attrname := ''Auth-Type'';
	reject_attr.attrvalue := ''Reject'';
	reject_attr.attrop := '':='';
	
	-- check input arguments
	IF $1 IS NULL OR nasipaddress IS NULL OR answer_call IS NULL OR $5 IS NULL OR $6 IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- remove RADIUS escapes
	username := radius_xlat($1);
	calling_station_id := radius_xlat($5);
	called_station_id := radius_xlat($6);
	
	RAISE LOG ''sqlbill: ARQ(username: %; IP: %; answer: %; calling: %; called: %)'', username, framed_ip, answer_call, calling_station_id, called_station_id;
	
	userid := match_user(username, framed_ip);
	IF userid IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- get user information
	SELECT INTO query_result a.id AS accid, balance, balancelimit, 
			currencysym, chappassword, allowedaliases, framedip, nasaddress
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id 
		WHERE a.closed IS NULL AND NOT a.disabled AND u.id = userid;
	IF NOT FOUND OR query_result.balance IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- check if the endpoint is allowed to access this NAS
	IF query_result.nasaddress IS NOT NULL THEN
		IF NOT (query_result.nasaddress >>= nasipaddress) THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
	END IF;

	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
		IF framed_ip IS NULL THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
		IF NOT (query_result.framedip >>= framed_ip) THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
	END IF;

	-- we do not need to check the account balance when answering the call
	IF NOT answer_call THEN
		-- get tariff for the destination called
		SELECT INTO trf * FROM match_tariff(called_station_id, 
			query_result.accid, query_result.currencysym);
		IF NOT FOUND OR trf.id IS NULL THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
	
		-- check if balance does not exceed the limit and there is enough money
		-- to talk for at least one minute
		IF trf.price > 0 THEN
			IF (query_result.balance - trf.price::NUMERIC(12,4)) 
					< query_result.balancelimit THEN
				RETURN NEXT reject_attr;
				RETURN;
			END IF;
		END IF;
	END IF;
	
	check_attr.id := 0;
	check_attr.attrname := ''User-Password'';
	check_attr.attrvalue := query_result.chappassword;
	check_attr.attrop := ''=='';
	RETURN NEXT check_attr;
	
	RETURN;
END;
' LANGUAGE 'plpgsql' CALLED ON NULL INPUT SECURITY INVOKER;

-- build a list of RADIUS reply attribute-value pairs for endpoint call admission request
-- $1 - User-Name
-- $2 - Framed-IP-Address
-- $3 - NAS-IP-Address
-- $4 - TRUE - the call is being answered, FALSE - the call is originated
-- $5 - calling station id
-- $6 - called station id
CREATE OR REPLACE FUNCTION radius_get_reply_arq_attrs(TEXT, INET, INET, BOOLEAN, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	nasipaddress ALIAS FOR $3;
	answer_call ALIAS FOR $4;
	username TEXT;
	calling_station_id TEXT;
	called_station_id TEXT;
	rcode_attr voipradattr%ROWTYPE;
	reply_attr voipradattr%ROWTYPE;
	attr_num INT := 1;
	userid INT;
	query_result RECORD;
	trf voiptariff%ROWTYPE;
BEGIN
	-- prepare h323-return-code avp, as it is referenced very often
	rcode_attr.id := attr_num;
	rcode_attr.attrname := ''h323-return-code'';
	rcode_attr.attrvalue := ''h323-return-code='';
	rcode_attr.attrop := ''='';
	attr_num := attr_num + 1;
	
	-- check input arguments
	IF $1 IS NULL OR nasipaddress IS NULL OR answer_call IS NULL OR $5 IS NULL OR $6 IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''11'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- remove RADIUS escapes
	username := radius_xlat($1);
	calling_station_id := radius_xlat($5);
	called_station_id := radius_xlat($6);
	
	userid := match_user(username, framed_ip);
	IF userid IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''1'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- get user information
	SELECT INTO query_result a.id AS accid, balance, balancelimit, currencysym, 
			chappassword, allowedaliases, framedip, nasaddress
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id 
		WHERE a.closed IS NULL AND NOT a.disabled AND NOT u.disabled 
			AND u.id = userid;
	IF NOT FOUND OR query_result.balance IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''1'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- check if the endpoint is allowed to access this NAS
	IF query_result.nasaddress IS NOT NULL THEN
		IF NOT (query_result.nasaddress >>= nasipaddress) THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
	END IF;

	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
		IF framed_ip IS NULL THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
		IF NOT (query_result.framedip >>= framed_ip) THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
	END IF;

	-- we do not need to check the account balance when answering the call
	IF NOT answer_call THEN
		-- get tariff for the destination called
		SELECT INTO trf * FROM match_tariff(called_station_id,
			query_result.accid, query_result.currencysym);
		IF NOT FOUND OR trf.id IS NULL THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''9'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
	
		-- check if balance does not exceed the limit and there is enough money
		-- to talk for at least one minute
		IF trf.price > 0 THEN
			IF (query_result.balance - trf.price::NUMERIC(12,4)) 
					< query_result.balancelimit THEN
				-- setup approtiate error code: 
				--   zero balance, credit limit, insufficient balance
				IF query_result.balance <= query_result.balancelimit THEN
					IF query_result.balancelimit = 0 THEN
						rcode_attr.attrvalue := rcode_attr.attrvalue || ''4'';
					ELSE
						rcode_attr.attrvalue := rcode_attr.attrvalue || ''6'';
					END IF;
				ELSE
					rcode_attr.attrvalue := rcode_attr.attrvalue || ''12'';
				END IF;
				RETURN NEXT rcode_attr;
				RETURN;
			END IF;
		END IF;

		IF trf.price > 0 THEN
			-- calculate credit time
			reply_attr.id := attr_num;
			reply_attr.attrname := ''h323-credit-time'';
			reply_attr.attrvalue := ''h323-credit-time='' 
				|| to_char(
					trunc((query_result.balance - query_result.balancelimit)
							/ trf.price::NUMERIC(12,4) * 60::NUMERIC(12,4), 0)
					,''FM9999999990'');
			reply_attr.attrop := ''='';
			RETURN NEXT reply_attr;
			attr_num := attr_num + 1;
		END IF;
	
		reply_attr.id := attr_num;
		reply_attr.attrname := ''h323-credit-amount'';
		reply_attr.attrvalue := ''h323-credit-amount='' 
			|| to_char(round(query_result.balance,2),''FM9999999990.00'');
		reply_attr.attrop := ''='';
		RETURN NEXT reply_attr;
		attr_num := attr_num + 1;
	
		reply_attr.id := attr_num;
		reply_attr.attrname := ''h323-currency'';
		reply_attr.attrvalue := ''h323-currency='' || query_result.currencysym;
		reply_attr.attrop := ''='';
		RETURN NEXT reply_attr;
		attr_num := attr_num + 1;
	
		reply_attr.id := attr_num;
		reply_attr.attrname := ''h323-billing-model'';
		reply_attr.attrvalue := ''h323-billing-model=2'';
		reply_attr.attrop := ''='';
		RETURN NEXT reply_attr;
		attr_num := attr_num + 1;
	END IF;
	
	-- append h323-return-code=0
	rcode_attr.attrvalue := rcode_attr.attrvalue || ''0'';
	RETURN NEXT rcode_attr;
	
	RETURN;
END;
' LANGUAGE 'plpgsql' CALLED ON NULL INPUT SECURITY INVOKER;

-- A compact function that returns RADIUS check AVPs 
-- for either RRQ, originating ARQ or answering ARQ
-- $1 - User-Name
-- $2 - Framed-IP-Address
-- $3 - NAS-IP-Address
-- $4 - is this RRQ (TRUE) or ARQ (FALSE)
-- $5 - is this answering ARQ (TRUE) or originating ARQ (FALSE)
-- $6 - Calling-Station-Id
-- $7 - Called-Station-Id
-- $8 - newline separated list of all Access-Request a=v pairs
CREATE OR REPLACE FUNCTION radius_get_check_attrs(TEXT, INET, INET, BOOLEAN, BOOLEAN, TEXT, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	username ALIAS FOR $1;
	framedipaddress ALIAS FOR $2;
	nasipaddress ALIAS FOR $3;
	registration ALIAS FOR $4;
	answer_call ALIAS FOR $5;
	calling_station_id ALIAS FOR $6;
	called_station_id ALIAS FOR $7;
	vplist ALIAS FOR $8;
	framed_ip INET;
	avp voipradattr%ROWTYPE;
BEGIN
	-- if Framed-IP-Address is not present, try to extract it from Cisco-AVPair
	framed_ip := COALESCE(framedipaddress, radius_get_ciscoavpair(vplist, ''h323-gw-address'')::INET);
	IF registration THEN
		FOR avp IN SELECT * FROM radius_get_check_rrq_attrs(username, framed_ip, nasipaddress, vplist) LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSIF answer_call THEN
		FOR avp IN SELECT * FROM 
			radius_get_check_arq_attrs(username, framed_ip, nasipaddress, TRUE, calling_station_id, called_station_id) 
		LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSE
		FOR avp IN SELECT * FROM 
			radius_get_check_arq_attrs(username, framed_ip, nasipaddress, FALSE, calling_station_id, called_station_id) 
		LOOP
			RETURN NEXT avp;
		END LOOP;
	END IF;
	RETURN;
END;
' LANGUAGE 'plpgsql' CALLED ON NULL INPUT SECURITY INVOKER;

-- A compact function that returns RADIUS reply AVPs 
-- for either RRQ, originating ARQ or answering ARQ
-- $1 - User-Name
-- $2 - Framed-IP-Address
-- $3 - NAS-IP-Address
-- $4 - is this RRQ (TRUE) or ARQ (FALSE)
-- $5 - is this answering ARQ (TRUE) or originating ARQ (FALSE)
-- $6 - Calling-Station-Id
-- $7 - Called-Station-Id
-- $8 - newline separated list of all Access-Request a=v pairs
CREATE OR REPLACE FUNCTION radius_get_reply_attrs(TEXT, INET, INET, BOOLEAN, BOOLEAN, TEXT, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	username ALIAS FOR $1;
	framedipaddress ALIAS FOR $2;
	nasipaddress ALIAS FOR $3;
	registration ALIAS FOR $4;
	answer_call ALIAS FOR $5;
	calling_station_id ALIAS FOR $6;
	called_station_id ALIAS FOR $7;
	vplist ALIAS FOR $8;
	framed_ip INET;
	avp voipradattr%ROWTYPE;
BEGIN
	-- if Framed-IP-Address is not present, try to extract it from Cisco-AVPair
	framed_ip := COALESCE(framedipaddress, radius_get_ciscoavpair(vplist, ''h323-gw-address'')::INET);
	IF registration THEN
		FOR avp IN SELECT * FROM radius_get_reply_rrq_attrs(username, framed_ip, nasipaddress, vplist) LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSIF answer_call THEN
		FOR avp IN SELECT * FROM 
			radius_get_reply_arq_attrs(username, framed_ip, nasipaddress, TRUE, calling_station_id, called_station_id) 
		LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSE
		FOR avp IN SELECT * FROM 
			radius_get_reply_arq_attrs(username, framed_ip, nasipaddress, FALSE, calling_station_id, called_station_id) 
		LOOP
			RETURN NEXT avp;
		END LOOP;
	END IF;
	RETURN;
END;
' LANGUAGE 'plpgsql' CALLED ON NULL INPUT SECURITY INVOKER;
