-- Calculate ASR (Average Service Ratio) and ACD (Average Call Duration) for a given route
-- Replace LIKE '705%' with a desired route prefix and '1 hour' with an interval to calculate the parameters
-- (the interval is measured from now back in the past)

CREATE TYPE voip_route_stats AS (
	prefix TEXT,
	totalcalls INT,
	totalminutes REAL,
	ASR REAL,
	ACD REAL
);

CREATE OR REPLACE FUNCTION voip_get_route_stats(TEXT, INTERVAL)
	RETURNS voip_route_stats AS
'
	SELECT
		$1::TEXT as prefix,
		COUNT(*)::INT AS totalcalls,
		SUM(COALESCE(duration,0))::REAL / 60::REAL AS totalminutes,
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR,
		SUM(COALESCE(duration,0))::REAL
			/ SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
				WHEN TRUE THEN 0 ELSE 1 END)::REAL AS ACD
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND (now() - acctstarttime) <= $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_route_stats(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS voip_route_stats AS
'
	SELECT 
		$1::TEXT as prefix,
		COUNT(*)::INT AS totalcalls,
		SUM(COALESCE(duration,0))::REAL / 60::REAL AS totalminutes,
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR,
		SUM(COALESCE(duration,0))::REAL 
			/ SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
				WHEN TRUE THEN 0 ELSE 1 END)::REAL AS ACD
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND acctstarttime BETWEEN $1 AND $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_route_asr(TEXT, INTERVAL)
	RETURNS REAL AS
'
	SELECT
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND (now() - acctstarttime) <= $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_route_asr(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT 
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND acctstarttime BETWEEN $1 AND $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_route_acd(TEXT, INTERVAL)
	RETURNS REAL AS
'
	SELECT SUM(COALESCE(duration,0))::REAL / COUNT(*)::REAL AS ACD
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND (now() - acctstarttime) <= $2 AND acctstoptime IS NOT NULL
			AND connecttime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_route_acd(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT SUM(COALESCE(duration,0))::REAL / COUNT(*)::REAL AS ACD
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND acctstarttime BETWEEN $1 AND $2 AND acctstoptime IS NOT NULL
			AND connecttime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_dst_stats(TEXT, INTERVAL)
	RETURNS voip_route_stats AS
'
	SELECT
		$1::TEXT as prefix,
		COUNT(*)::INT AS totalcalls,
		SUM(COALESCE(duration,0))::REAL / 60::REAL AS totalminutes,
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR,
		SUM(COALESCE(duration,0))::REAL
			/ SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
				WHEN TRUE THEN 0 ELSE 1 END)::REAL AS ACD
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND (now() - acctstarttime) <= $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_dst_stats(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS voip_route_stats AS
'
	SELECT 
		$1::TEXT as prefix,
		COUNT(*)::INT AS totalcalls,
		SUM(COALESCE(duration,0))::REAL / 60::REAL AS totalminutes,
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR,
		SUM(COALESCE(duration,0))::REAL 
			/ SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
				WHEN TRUE THEN 0 ELSE 1 END)::REAL AS ACD
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND acctstarttime BETWEEN $1 AND $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_dst_asr(TEXT, INTERVAL)
	RETURNS REAL AS
'
	SELECT
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2)
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND (now() - acctstarttime) <= $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_dst_asr(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT 
		SUM(CASE connecttime IS NULL OR terminatecause >= ''20''::CHAR(2) 
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND acctstarttime BETWEEN $1 AND $2 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_dst_acd(TEXT, INTERVAL)
	RETURNS REAL AS
'
	SELECT
		SUM(COALESCE(duration,0))::REAL / COUNT(*)::REAL AS ACD
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND (now() - acctstarttime) <= $2 AND acctstoptime IS NOT NULL
			AND connecttime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_dst_acd(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT SUM(COALESCE(duration,0))::REAL / COUNT(*)::REAL AS ACD
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND acctstarttime BETWEEN $1 AND $2 AND acctstoptime IS NOT NULL
			AND connecttime IS NOT NULL;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_total_dst_stats(INTERVAL)
	RETURNS SETOF voip_route_stats AS
'
	SELECT tariffdesc::TEXT, COUNT(*)::INT,
			SUM(COALESCE(duration, 0))::REAL / 60::REAL,
			voip_get_dst_asr(tariffdesc, $1), COALESCE(voip_get_dst_acd(tariffdesc, $1), 0)::REAL
		FROM voipcall WHERE NULLIF(tariffdesc, '''') IS NOT NULL AND acctstoptime IS NOT NULL
			AND (now() - acctstarttime) <= $1 GROUP BY tariffdesc;
' LANGUAGE SQL;

CREATE OR REPLACE FUNCTION voip_get_total_dst_stats(TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS SETOF voip_route_stats AS
'
	SELECT tariffdesc::TEXT, COUNT(*)::INT,
			SUM(COALESCE(duration, 0))::REAL / 60::REAL,
			voip_get_dst_asr(tariffdesc, $1, $2), COALESCE(voip_get_dst_acd(tariffdesc, $1, $2), 0)::REAL
		FROM voipcall WHERE NULLIF(tariffdesc, '''') IS NOT NULL AND acctstoptime IS NOT NULL
			AND acctstarttime BETWEEN $1 AND $2 GROUP BY tariffdesc;
' LANGUAGE SQL;
