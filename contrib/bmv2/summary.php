
<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT
		EXTRACT(year FROM acctstarttime) AS "Year", 
		EXTRACT(month from acctstarttime) AS "Month",
		CAST(SUM(COALESCE(cost, 0)) AS TEXT) || ' ' || currencysym AS "Cost",
		COUNT(*) AS "Calls",
		SUM(COALESCE(duration, 0))  AS "Minutes",
		CAST(ROUND(SUM(COALESCE(cost, 0)) / COUNT(*), 6) AS TEXT) || ' ' || currencysym AS "Average"
	FROM voipcall
	WHERE connecttime IS NOT NULL AND acctstoptime IS NOT NULL 
		AND cost IS NOT NULL 
	GROUP BY EXTRACT(year FROM acctstarttime), EXTRACT(month from acctstarttime), currencysym 
	ORDER BY 1 ASC, 2 ASC, currencysym ASC";

print("<H1 align =\"center\">Call termination summary   </H1>");

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");
$rows = pg_num_rows($result);

	print("<table align=\"center\"/>");
	print("<tr/> ");
	print("<td>Year </td> ");
	print("<td>Month </td> ");
	print("<td>Total Cost </td> ");
	print("<td>Calls Connected</td> ");
	print("<td>Total Minutes </td> ");
	print("<td>Avg Duration </td> ");
	print("</tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$year = pg_result($result, $li, 0);
	$month = pg_result($result, $li, 0);
	$cost = pg_result($result, $li, 0);
	$calls = pg_result($result, $li, 0);
	$minutes = pg_result($result, $li, 0);
	$avg = pg_result($result, $li, 1);
	print("<tr/> ");
	print("<td>$year </td> ");
	print("<td>$month </td> ");
	print("<td>$cost </td> ");
	print("<td>$calls </td> ");
	print("<td>$minutes </td> ");
	print("<td>$avg </td> ");
	print("</tr> ");
	}
	print("</table>");

pg_close($connection);
include "../local/tail.php";
?>

