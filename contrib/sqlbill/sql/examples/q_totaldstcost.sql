-- Report per-destination cost over a specified time period
-- Adjust the period using BETWEEN clause (you can also use
--  AND acctstarttime >= (now() - '2 days'::INTERVAL))
SELECT tariffdesc AS "Destination", COUNT(*) AS "Total Calls",
		ROUND(SUM(COALESCE(duration, 0))::NUMERIC / 60::NUMERIC, 1) AS "Total Minutes",
		SUM(COALESCE(cost, 0)) AS "Cost", currencysym AS "Currency"
	FROM voipcall
	WHERE connecttime IS NOT NULL AND currencysym IS NOT NULL AND tariffdesc IS NOT NULL
		AND acctstarttime BETWEEN '00:00:00 Jan 1, 2004' AND '23:59:59 Dec 31, 2004'
	GROUP BY tariffdesc, currencysym
	ORDER BY 4 DESC, 5 DESC;
