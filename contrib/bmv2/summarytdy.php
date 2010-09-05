
<html>
<head>
<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
<META HTTP-EQUIV="Expires" CONTENT="-1">
<META HTTP-EQUIV="Refresh" CONTENT="60">
</head>
<body>
<?php
include "local/connect.php";


$query = "SELECT count(*), sum(duration)/60, sum(cost) from voipcall where acctstarttime::timestamp > current_date ;";

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


$query = "SELECT h323id, prefix, count(*), sum(duration)/60, sum(cost), tariffdesc 
        from voipcall 
        where acctstarttime::timestamp > current_date 
        group by prefix,tariffdesc, h323id 
        order by tariffdesc, prefix;";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr><td>Originating &nbsp; </td> <td> Prefix </td> <td> Destination &nbsp;</td>  ");
	print("<td> Calls &nbsp; <td>Duration (mins) &nbsp;<td>Cost (Euros) </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$origin = pg_result($result, $li, 0);
	$prefix = pg_result($result, $li, 1);
	$calls = pg_result($result, $li, 2);
	$duration = number_format(pg_result($result, $li, 3), 2);
	$cost = number_format(pg_result($result, $li, 4), 2);
	$dest = pg_result($result, $li, 5);

	print("<tr><td>$origin &nbsp; <td> $prefix &nbsp; </td> <td>$dest</td> ");
	print("<td> $calls &nbsp; </td> <td>$duration &nbsp; <td> $cost &nbsp; </tr> ");
	}
	print("</table>");


	print("<p></p>");
	print("<p></p>");
// calls in progress ----------------------------------------------------------
	print("<p></p>");
$query = "SELECT callingstationid, prefix, calledstationid, tariffdesc, acctstarttime
        from voipcall where connecttime is not null and disconnecttime IS NULL ";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");
	$rows = pg_num_rows($result);

	print("<H2 align=\"center\">$rows calls in progress<br> </H2>");

	print("<table frame=border align=\"center\">");

	print("<tr><td>Time</td><td>Caller &nbsp; </td><td> Called &nbsp;</td>  ");
	print("<td> Prefix &nbsp; </td> <td> Destination &nbsp; </td>
                <td> &nbsp;</td> </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$caller = pg_result($result, $li, 0);
	$prefix = pg_result($result, $li, 1);
	$called = pg_result($result, $li, 2);
	$dest = pg_result($result, $li, 3);
	$time = pg_result($result, $li, 4);

	print("<tr><td>$time</td><td>$caller &nbsp;</td> <td> $called &nbsp;</td>  ");
	print("<td> $prefix &nbsp; </td><td> $dest &nbsp; </td> <td> &nbsp; </td></tr> ");

	}
	print("</table>");

pg_close($connection);

?>
</body>
</html>
