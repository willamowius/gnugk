-- RADIUS ARQ/RRQ processing functions
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
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

-- build a list of RADIUS check attribute-value pairs for endpoint registration request
-- $1 - User-Name
-- $2 - Framed-IP-Address
-- $3 - h323-ivr-in
CREATE OR REPLACE FUNCTION radius_get_check_rrq_attrs(TEXT, INET, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	username TEXT;
	h323ivrout TEXT;
	reject_attr voipradattr%ROWTYPE;
	check_attr voipradattr%ROWTYPE;
	query_result RECORD;
	userid INT;
BEGIN
	-- prepare Auth-Type := Reject avp, as it is referenced very often
	reject_attr.id := 0;
	reject_attr.attrname := ''Auth-Type'';
	reject_attr.attrvalue := ''Reject'';
	reject_attr.attrop := '':='';
	
	-- check input parameters
	IF $1 IS NULL OR $2 IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- remove RADIUS escapes
	username := radius_xlat($1);

	userid := match_user(username, framed_ip);
	IF userid IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
		
	-- get user information
	SELECT INTO query_result chappassword, allowedaliases, framedip 
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id 
		WHERE a.closed IS NULL AND NOT a.disabled AND u.id = userid;
	IF NOT FOUND OR query_result.chappassword IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
		IF NOT (query_result.framedip >>= framed_ip) THEN
			RETURN NEXT reject_attr;
			RETURN;
		END IF;
	END IF;
	
	-- check if all endpoint aliases are allowed
	IF $3 IS NOT NULL THEN
		h323ivrout := radius_xlat(trim($3));
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
-- $3 - h323-ivr-in
CREATE OR REPLACE FUNCTION radius_get_reply_rrq_attrs(TEXT, INET, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	username TEXT;
	h323ivrout TEXT;
	rcode_attr voipradattr%ROWTYPE;
	reply_attr voipradattr%ROWTYPE;
	attr_num INT := 1;
	userid INT;
	query_result RECORD;
BEGIN
	-- prepare h323-return-code avp, as it is referenced very often
	rcode_attr.id := attr_num;
	rcode_attr.attrname := ''h323-return-code'';
	rcode_attr.attrvalue := ''h323-return-code='';
	rcode_attr.attrop := ''='';
	attr_num := attr_num + 1;
	
	-- check input parameters
	IF $1 IS NULL OR $2 IS NULL THEN
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
	SELECT INTO query_result balance, currencysym, allowedaliases, 
			assignaliases, framedip 
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id
		WHERE a.closed IS NULL AND NOT a.disabled AND u.id = userid;
	IF NOT FOUND OR query_result.balance IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''1'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
		IF NOT (query_result.framedip >>= framed_ip) THEN
			rcode_attr.attrvalue := rcode_attr.attrvalue || ''7'';
			RETURN NEXT rcode_attr;
			RETURN;
		END IF;
	END IF;
	
	-- check if all endpoint aliases are allowed
	IF $3 IS NOT NULL THEN
		h323ivrout := radius_xlat(trim($3));
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
-- $3 - TRUE - the call is being answered, FALSE - the call is originated
-- $4 - calling station id
-- $5 - called station id
CREATE OR REPLACE FUNCTION radius_get_check_arq_attrs(TEXT, INET, BOOLEAN, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	answer_call ALIAS FOR $3;
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
	IF $1 IS NULL OR $2 IS NULL OR $3 IS NULL OR $4 IS NULL OR $5 IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- remove RADIUS escapes
	username := radius_xlat($1);
	calling_station_id := radius_xlat(trim($4));
	called_station_id := radius_xlat(trim($5));
	
	userid := match_user(username, framed_ip);
	IF userid IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- get user information
	SELECT INTO query_result a.id AS accid, balance, balancelimit, 
			currencysym, chappassword, allowedaliases, framedip 
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id 
		WHERE a.closed IS NULL AND NOT a.disabled AND u.id = userid;
	IF NOT FOUND OR query_result.balance IS NULL THEN
		RETURN NEXT reject_attr;
		RETURN;
	END IF;
	
	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
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
-- $3 - TRUE - the call is being answered, FALSE - the call is originated
-- $4 - calling station id
-- $5 - called station id
CREATE OR REPLACE FUNCTION radius_get_reply_arq_attrs(TEXT, INET, BOOLEAN, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	framed_ip ALIAS FOR $2;
	answer_call ALIAS FOR $3;
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
	IF $1 IS NULL OR $2 IS NULL OR $3 IS NULL OR $4 IS NULL OR $5 IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''11'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- remove RADIUS escapes
	username := radius_xlat($1);
	calling_station_id := radius_xlat(trim($4));
	called_station_id := radius_xlat(trim($5));
	
	userid := match_user(username, framed_ip);
	IF userid IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''1'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- get user information
	SELECT INTO query_result a.id AS accid, balance, balancelimit, currencysym, 
			chappassword, allowedaliases, framedip 
		FROM voipuser u JOIN voipaccount a ON u.accountid = a.id 
		WHERE a.closed IS NULL AND NOT a.disabled AND NOT u.disabled 
			AND u.id = userid;
	IF NOT FOUND OR query_result.balance IS NULL THEN
		rcode_attr.attrvalue := rcode_attr.attrvalue || ''1'';
		RETURN NEXT rcode_attr;
		RETURN;
	END IF;
	
	-- check if the endpoint IP address matches
	IF query_result.framedip IS NOT NULL THEN
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
-- $3 - is this RRQ (TRUE) or ARQ (FALSE)
-- $4 - is this answering ARQ (TRUE) or originating ARQ (FALSE)
-- $5 - Calling-Station-Id
-- $6 - Called-Station-Id
-- $7 - h323-ivr-out
CREATE OR REPLACE FUNCTION radius_get_check_attrs(TEXT, INET, BOOLEAN, BOOLEAN, TEXT, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	username ALIAS FOR $1;
	framed_ip ALIAS FOR $2;
	registration ALIAS FOR $3;
	answer_call ALIAS FOR $4;
	calling_station_id ALIAS FOR $5;
	called_station_id ALIAS FOR $6;
	h323ivrout ALIAS FOR $7;
	avp voipradattr%ROWTYPE;
BEGIN
	IF registration THEN
		FOR avp IN SELECT * FROM radius_get_check_rrq_attrs(username, framed_ip, h323ivrout) LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSIF answer_call THEN
		FOR avp IN SELECT * FROM 
			radius_get_check_arq_attrs(username, framed_ip, TRUE, calling_station_id, called_station_id) 
		LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSE
		FOR avp IN SELECT * FROM 
			radius_get_check_arq_attrs(username, framed_ip, FALSE, calling_station_id, called_station_id) 
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
-- $3 - is this RRQ (TRUE) or ARQ (FALSE)
-- $4 - is this answering ARQ (TRUE) or originating ARQ (FALSE)
-- $5 - Calling-Station-Id
-- $6 - Called-Station-Id
-- $7 - h323-ivr-out

CREATE OR REPLACE FUNCTION radius_get_reply_attrs(TEXT, INET, BOOLEAN, BOOLEAN, TEXT, TEXT, TEXT)
	RETURNS SETOF voipradattr AS
'
DECLARE
	username ALIAS FOR $1;
	framed_ip ALIAS FOR $2;
	registration ALIAS FOR $3;
	answer_call ALIAS FOR $4;
	calling_station_id ALIAS FOR $5;
	called_station_id ALIAS FOR $6;
	h323ivrout ALIAS FOR $7;
	avp voipradattr%ROWTYPE;
BEGIN
	IF registration THEN
		FOR avp IN SELECT * FROM radius_get_reply_rrq_attrs(username, framed_ip, h323ivrout) LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSIF answer_call THEN
		FOR avp IN SELECT * FROM 
			radius_get_reply_arq_attrs(username, framed_ip, TRUE, calling_station_id, called_station_id) 
		LOOP
			RETURN NEXT avp;
		END LOOP;
	ELSE
		FOR avp IN SELECT * FROM 
			radius_get_reply_arq_attrs(username, framed_ip, FALSE, calling_station_id, called_station_id) 
		LOOP
			RETURN NEXT avp;
		END LOOP;
	END IF;
	RETURN;
END;
' LANGUAGE 'plpgsql' CALLED ON NULL INPUT SECURITY INVOKER;
