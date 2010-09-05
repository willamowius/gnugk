<?php

include "../local/top.php";
include "../local/connect.php";

print("<H1 align =\"center\">Today's ASR and ACDs <br> </H1>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

$query = "SELECT tariffdesc, sum(case when duration > graceperiod then '1' else '0' end::NUMERIC) , sum(duration), count(*) 
        from voipcall where disconnecttime::timestamp > current_date 
        group by tariffdesc order by tariffdesc;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table  align=\"center\">");

$tasr = 0;
$tcd = 0;
$tcount = 0;

	print("<tr><td>Destination &nbsp;<td>ASR &nbsp; <td> ACD (mins)&nbsp; <td> Calls &nbsp; </tr> ");
	print("<tr></tr>");
	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$destination = pg_result($result, $li, 0);

	$good = pg_result($result, $li, 1);
	$tasr = $tasr + $good;
	$tcd = $tcd + $durn;

	$durn = pg_result($result, $li, 2);
	$count = pg_result($result, $li, 3);
	$tcount = $tcount + $count; 
	if($good > 0)
		{
		$acd = number_format(($durn/$good) / 60, 2);
		$asr = number_format(($good/$count) * 100, 2);
		}
	else
		{
		$acd = 0;
		$asr = 0;
		};

	print("<tr><td>$destination &nbsp;<td>$asr% &nbsp; <td> $acd &nbsp; <td> $count &nbsp; </tr> ");
	};
	print("<tr></tr>");
	$tasr  = number_format(($tasr/$tcount) * 100, 2);
	$tacd  = number_format(($tcd/$tcount) / 60, 2);

	print("<tr><td>TOTAL&nbsp;<td>$tasr% &nbsp; <td> $tacd &nbsp; <td> $tcount &nbsp; </tr> ");
	print("\n</table >");

	print("<p></p>");
	print("<p></p>");

	print("<p align=\"center\" />ACD includes only good calls. ");
	print("Good calls are defined as having a duration more than the grace period.</p>");
	print("<p></p>");
	print("<p></p>");

echo '<hr>' ;

$query = "SELECT disconnecttime, h323id, callingstationid, calledstationid, duration from voipcall
         where (terminatecause = '10' OR terminatecause = '0') AND duration < graceperiod 
         and disconnecttime::timestamp > current_date ;";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

print("<H2 align=\"center\">There were $rows calls of less than the grace period. </H2>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

	print("<table frame=border align=\"center\">");
	print("<tr><td>Time <td>Originator &nbsp; <td> Caller &nbsp; <td>Called &nbsp; <td>Duration &nbsp;  ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$time = substr(pg_result($result, $li, 0), 0, 8);
	$origin = pg_result($result, $li, 1);
	$carrier = pg_result($result, $li, 2);
	$ani = pg_result($result, $li, 3);
	$duration = pg_result($result, $li, 4);

	print("<tr><td> $time</td> <td>$origin &nbsp; <td> $carrier &nbsp; <td> $ani &nbsp; <td> $duration &nbsp; ");

	}

	print("</table >");

	print("<p></p>");
	print("<p></p>");

pg_close($connection);
include "../local/tail.php";

?>

