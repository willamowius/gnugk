
<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT count(*), sum(duration)/60, sum(cost) from voipcall 
        where disconnecttime::timestamp between ( current_date - 1) and current_date ;";

print("<H1 align =\"center\"/>Summary for Yesterday <br> </H1>");
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
        where disconnecttime::timestamp between ( current_date - 1) and current_date 
        group by tariffdesc, h323id order by tariffdesc ";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr><td>Originator &nbsp; </td><td> Destination &nbsp;</td>  ");
	print("<td> Calls &nbsp; </td><td>Duration (mins) &nbsp;<td>Cost</td>  ");
	print(" <td>Avg Duration </td> <td>Avg Cost</td>  </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$origin = pg_result($result, $li, 0);
	$carrier = pg_result($result, $li, 1);
	$calls = pg_result($result, $li, 2);
	$duration = pg_result($result, $li, 3);
	$cost = pg_result($result, $li, 4);
        $avg_cost = $cost / $calls ;
        $avg_duration = $duration / $calls;
	$duration = number_format($duration, 2);
	$cost = number_format($cost, 2);

	$avg_duration = number_format($avg_duration, 2);
	$avg_cost = number_format($avg_cost, 2);


	print("<tr><td>$origin &nbsp; </td><td> $carrier &nbsp; </td> ");
	print("<td> $calls &nbsp;</td> <td>$duration &nbsp; </td><td> $cost &nbsp;</td>  ");
	print(" <td>$avg_duration &nbsp; </td><td> $avg_cost &nbsp;</td> </tr> ");
	}
	print("</table>");


	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

pg_close($connection);
include "../local/tail.php";

?>

