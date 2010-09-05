
<html>
<head></head>
<body>
<?php
include "../local/connect.php";

print("<H1 align =\"center\">Yesterday's ASR and ACD listing <br> </H1>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

$query = "SELECT tariffdesc, count(*), sum(CASE WHEN (duration > graceperiod) THEN '1' ELSE '0' END::NUMERIC), sum(duration)/ '60'
        from voipcall where acctstarttime between (current_date - 1) and current_date group by tariffdesc order by tariffdesc;";


$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");

$tasr = 0;
$tcd = 0;
$tcount = 0;

	print("<tr><td>Destination &nbsp;</td><td>ASR &nbsp;</td> <td> ACD (mins)&nbsp;</td> <td> Calls &nbsp;</td> </tr> ");
	print("<tr></tr>");
	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$destination = pg_result($result, $li, 0);

	$calls = pg_result($result, $li, 1);
	$success = pg_result($result, $li, 2);

	$duration = pg_result($result, $li, 3);
	$acd = number_format(($duration / $calls  ), 2);
	$asr = number_format( $success / $calls * 100, 2);

	print("<tr><td>$destination &nbsp;</td><td>$asr% &nbsp;</td> <td> $acd &nbsp; </td><td> $calls &nbsp;</td> </tr> ");
	};
	print("<tr></tr>");

	print("\n</table >");

	print("<p></p>");
	print("<p></p>");

	print("<p align=\"center\" />ACD includes only calls ");
	print("having a duration longer than the grace period.<br>");
	print("<p></p>");
	print("<p></p>");


	print("<p></p>");
	print("<p></p>");

pg_close($connection);

?>
</body>
</html>

