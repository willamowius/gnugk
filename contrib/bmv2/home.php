
<?php
include "./local/top.php";
include "./local/connect.php";

$query = "SELECT count(*), sum(duration)/60, sum(cost) 
	from voipcall where acctstarttime::timestamp > current_date ;";

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


$query = "SELECT h323id, prefix, count(*), sum(duration)/60, sum(cost) 
	from voipcall where acctstoptime::timestamp > current_date 
	group by h323id, prefix ";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr> <td> Calling &nbsp; </td> <td> Called &nbsp;  </td> ");
	print("<td> Calls &nbsp; </td>  <td>Duration (mins) &nbsp </td> <td>Cost </td>  </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$ani = pg_result($result, $li, 0);
	$dni = pg_result($result, $li, 1);
	$calls = pg_result($result, $li, 2);
	$duration = number_format(pg_result($result, $li, 3), 2);
	$cost = number_format(pg_result($result, $li, 4), 2);
	print("<tr><td> $ani &nbsp; </td> <td> $dni &nbsp;  </td> ");
	print("<td> $calls &nbsp; </td>  <td>$duration &nbsp;  </td> <td> $cost &nbsp; </td>  </tr> ");
	}
	print("</table>");


	print("<p></p>");
	print("<p></p>");
	print("<p></p>");
$query = "SELECT callingstationid, calledstationid, duration, prefix
	from voipcall where disconnecttime IS NULL 
        and connecttime is not null
	order by callingstationid, calledstationid ";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");
	$rows = pg_num_rows($result);

	print("<H2 align=\"center\">$rows calls in progress<br> </H2>");

	print("<table frame=border align=\"center\">");

	print("<tr> <td> Calling &nbsp;  </td> <td> Called &nbsp; </td> ");
	print(" <td>Prefix</td><td>Duration (secs) &nbsp;  </td> </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$ani = pg_result($result, $li, 0);
	$dni = pg_result($result, $li, 1);
	$duration = substr(pg_result($result, $li, 2), 0, 5);
	$prefix = pg_result($result, $li, 3);
	print("<tr> <td> $ani &nbsp; </td> <td> $dni &nbsp; </td> <td> $prefix</td> ");
	print(" <td>$duration &nbsp; </td> </tr> ");

	}
	print("</table>");

pg_close($connection);
include "./local/tail.php";
?>

