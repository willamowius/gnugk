-- Get per-destination call statistics
-- Adjust time interval for voip_get_total_dst_stats
-- (you can also query for a specific time interval
--  by using voip_get_total_dst_stats('00:00:00 Nov 1, 2004', '23:59:59 Nov 30, 2004'))
-- and change sorting order through the ORDER BY clause
--
-- This query can run for a while and requires route/destination functions
-- to be present (you can create them using c_reports.sql script)
SELECT prefix AS "Destination", totalcalls AS "Total Calls", 
		ROUND(totalminutes::NUMERIC, 1) AS "Total Minutes",
		ROUND((asr*100)::NUMERIC, 2) AS "ASR [%]", 
		ROUND(acd::NUMERIC, 0)::INT AS "ACD [s]"
	FROM voip_get_total_dst_stats('1 day')
	ORDER BY 4 DESC, 2 DESC;
