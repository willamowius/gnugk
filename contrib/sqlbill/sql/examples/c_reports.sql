-- Calculate ASR (Average Service Ratio) and ACD (Average Call Duration) 
-- for a given route or all routes

-- route statistics
CREATE TYPE voip_route_stats AS (
	-- route prefix
	prefix TEXT,
	-- total calls routed (connected and unconnected)
	totalcalls INT,
	-- total minutes routed
	totalminutes REAL,
	-- Average Service Ration (0..1)
	ASR REAL,
	-- Average Call Duration (seconds)
	ACD REAL
);

-- Get route statistics for the given time interval
-- $1 - route prefix
-- $2 - time interval begin
-- $3 - time interval end
CREATE OR REPLACE FUNCTION voip_get_route_stats(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS voip_route_stats AS
'
	SELECT 
		$1::TEXT as prefix,
		COUNT(*)::INT AS totalcalls,
		SUM(COALESCE(duration,0))::REAL / 60::REAL AS totalminutes,
		SUM(CASE connecttime IS NULL OR (COALESCE(duration, 0) <= 60 AND terminatecause >= ''20''::CHAR(2))
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR,
		SUM(COALESCE(duration,0))::REAL 
			/ SUM(CASE connecttime IS NULL OR (COALESCE(duration, 0) <= 60 AND terminatecause >= ''20''::CHAR(2))
				WHEN TRUE THEN 0 ELSE 1 END)::REAL AS ACD
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND acctstarttime BETWEEN $2 AND $3 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

-- Get route ASR for the given time interval
-- $1 - route prefix
-- $2 - time interval begin
-- $3 - time interval end
CREATE OR REPLACE FUNCTION voip_get_route_asr(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT 
		SUM(CASE connecttime IS NULL OR (COALESCE(duration, 0) <= 60 AND terminatecause >= ''20''::CHAR(2))
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND acctstarttime BETWEEN $2 AND $3 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

-- Get route ACD for the given time interval
-- $1 - route prefix
-- $2 - time interval begin
-- $3 - time interval end
CREATE OR REPLACE FUNCTION voip_get_route_acd(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT SUM(COALESCE(duration,0))::REAL / COUNT(*)::REAL AS ACD
		FROM voipcall WHERE calledstationid LIKE $1 || ''%''
			AND acctstarttime BETWEEN $2 AND $3 AND acctstoptime IS NOT NULL
			AND connecttime IS NOT NULL;
' LANGUAGE SQL;

-- Get destination (tariff) statistics for the given time interval
-- $1 - destination name from the tariff table
-- $2 - time interval begin
-- $3 - time interval end
CREATE OR REPLACE FUNCTION voip_get_dst_stats(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS voip_route_stats AS
'
	SELECT 
		$1::TEXT as prefix,
		COUNT(*)::INT AS totalcalls,
		SUM(COALESCE(duration,0))::REAL / 60::REAL AS totalminutes,
		SUM(CASE connecttime IS NULL OR (COALESCE(duration, 0) <= 60 AND terminatecause >= ''20''::CHAR(2))
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR,
		SUM(COALESCE(duration,0))::REAL 
			/ SUM(CASE connecttime IS NULL OR (COALESCE(duration, 0) <= 60 AND terminatecause >= ''20''::CHAR(2))
				WHEN TRUE THEN 0 ELSE 1 END)::REAL AS ACD
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND acctstarttime BETWEEN $2 AND $3 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

-- Get destination (tariff) ASR for the given time interval
-- $1 - destination name from the tariff table
-- $2 - time interval begin
-- $3 - time interval end
CREATE OR REPLACE FUNCTION voip_get_dst_asr(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT 
		SUM(CASE connecttime IS NULL OR (COALESCE(duration, 0) <= 60 AND terminatecause >= ''20''::CHAR(2))
			WHEN TRUE THEN 0 ELSE 1 END)::REAL / COUNT(*)::REAL AS ASR
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND acctstarttime BETWEEN $2 AND $3 AND acctstoptime IS NOT NULL;
' LANGUAGE SQL;

-- Get destination (tariff) ACD for the given time interval
-- $1 - destination name from the tariff table
-- $2 - time interval begin
-- $3 - time interval end
CREATE OR REPLACE FUNCTION voip_get_dst_acd(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS REAL AS
'
	SELECT SUM(COALESCE(duration,0))::REAL / COUNT(*)::REAL AS ACD
		FROM voipcall WHERE COALESCE(tariffdesc, '''') = $1
			AND acctstarttime BETWEEN $2 AND $3 AND acctstoptime IS NOT NULL
			AND connecttime IS NOT NULL;
' LANGUAGE SQL;

-- Get total per-destination statistics for the given time interval
-- $1 - time interval begin
-- $2 - time interval end
CREATE OR REPLACE FUNCTION voip_get_total_dst_stats(TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE)
	RETURNS SETOF voip_route_stats AS
'
	SELECT tariffdesc::TEXT, COUNT(*)::INT,
			SUM(COALESCE(duration, 0))::REAL / 60::REAL,
			voip_get_dst_asr(tariffdesc, $1, $2), COALESCE(voip_get_dst_acd(tariffdesc, $1, $2), 0)::REAL
		FROM voipcall WHERE NULLIF(tariffdesc, '''') IS NOT NULL AND acctstoptime IS NOT NULL
			AND acctstarttime BETWEEN $1 AND $2 GROUP BY tariffdesc;
' LANGUAGE SQL;
