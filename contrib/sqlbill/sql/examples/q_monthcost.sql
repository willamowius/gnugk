-- Monthly usage statistics
SELECT
		EXTRACT(year FROM acctstarttime) AS "Year", 
		EXTRACT(month from acctstarttime) AS "Month",
		CAST(SUM(COALESCE(cost, 0)) AS TEXT) || ' ' || currencysym AS "Total Cost",
		COUNT(*) AS "Total Connected Calls",
		SUM(COALESCE(duration, 0)) / 60 AS "Total Minutes",
		CAST(ROUND(SUM(COALESCE(cost, 0)) / COUNT(*), 6) AS TEXT) || ' ' || currencysym AS "Average Minute Cost"
	FROM voipcall
	WHERE connecttime IS NOT NULL AND acctstoptime IS NOT NULL 
		AND cost IS NOT NULL 
	GROUP BY EXTRACT(year FROM acctstarttime), EXTRACT(month from acctstarttime), currencysym 
	ORDER BY 1 ASC, 2 ASC, currencysym ASC;
