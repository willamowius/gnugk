
<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT count(*), sum(duration)/60, sum(cost) from voipcall 
        where disconnecttime::timestamp > current_date ;";

print("<H1 align =\"center\"/>Summary for today (so far) <br> </H1>");
	print("<p></p>");
	print("<p></p>");

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");


	$rows = pg_num_rows($result);

	$calls = pg_result($result, 0, 0);
	$duration = number_format(pg_result($result, 0, 1), 2);
	$cost = number_format(pg_result($result, 0, 2), 2);

	print("<H2 align=\"center\">Calls: $calls / ");
	print(" Duration: $duration  (mins) / ");
	print("Cost (Eur): $cost  <br> </H2>");
	print("<p></p>");


$query = "SELECT h323id, tariffdesc, count(*), sum(duration)/60, sum(cost) from voipcall 
        where disconnecttime::timestamp > current_date 
        group by tariffdesc, h323id order by tariffdesc ";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr><td>Originator &nbsp; <td> Destination &nbsp;  ");
	print("<td> Calls &nbsp; </td><td>Duration &nbsp;</td><td>Cost</td> ");
	print("<td> Avg Duration &nbsp;</td><td>Avg Cost  </td></tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$origin = pg_result($result, $li, 0);
	$destination = pg_result($result, $li, 1);
	$calls = pg_result($result, $li, 2);
	$duration = number_format(pg_result($result, $li, 3), 2);
	$cost = pg_result($result, $li, 4);
        $avg_duration = $duration / $calls;
        $avg_cost = $cost / $calls;
	$cost = number_format($cost, 2);
	$avg_cost = number_format($avg_cost, 2);
	$duration = number_format($duration, 2);
	$avg_duration = number_format($avg_duration, 2);
        
	print("<tr><td>$origin &nbsp; <td> $destination &nbsp;  ");
	print("<td> $calls &nbsp; <td>$duration &nbsp; <td> $cost &nbsp; </tr> ");
	print(" <td>$avg_duration &nbsp; <td> $avg_cost &nbsp; </tr> ");
	}
	print("</table>");


	print("<p></p>");
	print("<p></p>");
	print("<p></p>");
$query = "SELECT h323id, callingstationid, calledstationid, duration 
                from voipcall 
                where connecttime is not null and disconnecttime IS NULL ";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");
	$rows = pg_num_rows($result);

	print("<H2 align=\"center\">$rows calls in progress<br> </H2>");

	print("<table frame=border align=\"center\">");

	print("<tr><td>Originator &nbsp; <td> Caller &nbsp;  ");
	print("<td> Called &nbsp; <td>Duration (secs) &nbsp; </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$origin = pg_result($result, $li, 0);
	$carrier = pg_result($result, $li, 1);
	$ani = pg_result($result, $li, 2);
	$duration = substr(pg_result($result, $li, 3), 0, 5);
	print("<tr><td>$origin &nbsp; <td> $carrier &nbsp;  ");
	print("<td> $ani &nbsp; <td>$duration &nbsp; </tr> ");

	}
	print("</table>");

pg_close($connection);
include "../local/top.php";

?>

