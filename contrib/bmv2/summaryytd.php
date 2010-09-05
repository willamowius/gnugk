<?php
include "../local/top.php";
include "local/connect.php";

print("<H1 align =\"center\"/>Yesterday (Summary)<br> </H1>");
	print("<p></p>");
	print("<p></p>");

$query = "SELECT COUNT(*), ROUND(SUM(COALESCE(duration, 0))::NUMERIC /60::NUMERIC , 1) ,
		SUM(COALESCE(cost, 0)) , currencysym	FROM voipcall
	WHERE  acctstarttime BETWEEN current_date - 1  AND current_date 
	GROUP BY currencysym
	ORDER BY 3 DESC, 4 DESC";

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");


	$rows = pg_num_rows($result);
//	$calls = number_format(pg_result($result, 0, 0), 0);
	$calls = pg_result($result, 0, 0);
//	$duration = number_format(pg_result($result, 0, 1), 2);
	$duration = pg_result($result, 0, 1);
//	$cost = number_format(pg_result($result, 0, 2), 2);
	$cost = pg_result($result, 0, 2);

	print("<H2 align=\"center\">Total number of calls: $calls  <br> </H2>");
	print("<H2 align=\"center\">Total Duration of calls: $duration  (mins) <br> </H2>");
	print("<H2 align=\"center\">Total Cost of calls : $cost  <br> </H2>");
	print("<p></p>");



$query = "SELECT h323id, prefix, count(*), sum(duration)/60, sum(cost) from voipcall 
        where disconnecttime::timestamp between current_date -1  and current_date 
                group by prefix, h323id ";
	
        $result = pg_query($connection, $query) 
                or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr><td>Originator &nbsp; <td> Prefix &nbsp;  ");
	print("<td> Calls &nbsp; <td>Duration (mins) &nbsp;<td>Cost (Euros) </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$origin = pg_result($result, $li, 0);
	$prefix = pg_result($result, $li, 1);
	$calls = pg_result($result, $li, 2);
	$duration = number_format(pg_result($result, $li, 3) , 2);
	$cost = number_format(pg_result($result, $li, 4), 2);
	print("<tr><td>$origin &nbsp; <td> $prefix &nbsp;  ");
	print("<td> $calls &nbsp; <td>$duration &nbsp; <td> $cost &nbsp; </tr> ");
	}
	print("</table>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");
$query = "SELECT prefix, count(*), sum(duration)/60, sum(cost) from voipcall 
                where disconnecttime::timestamp between (current_date - 1) and current_date  
                group by prefix;";
	$result = pg_query($connection, $query) or die(" Unable to query the database ");
	$rows = pg_num_rows($result);
print("<table  align=\"center\">");
	print("<tr><td>Prefix &nbsp; <td> Calls &nbsp; <td>Minutes &nbsp;<td>Euros &nbsp; </tr> ");
for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$prefix = pg_result($result, $li, 0);
	$calls = pg_result($result, $li, 1);
	$duration = number_format(pg_result($result, $li, 2), 2);
	$cost = number_format(pg_result($result, $li, 3), 2);
if ($cost > 0)
		{
		print("<tr><td> $prefix &nbsp; <td>$calls &nbsp; <td>$duration &nbsp; <td> $cost &nbsp; </tr> ");

		}
	}
	print("</table>");
	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

pg_close($connection);
include "../local/top.php";

?>

