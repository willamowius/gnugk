
<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT c.tariffdesc,  count(*), c.terminatecause, q.desc_short 
        from voipcall as c join q931_codes as q on c.terminatecause = q.q931_code 
        where c.terminatecause <> '0' and c.terminatecause <> '10' 
        and disconnecttime > current_date
        group by c.tariffdesc, c.terminatecause, q.desc_short 
        order by c.tariffdesc, c.terminatecause ;";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

print("<H2 align=\"center\"> Bad calls categorised by Q931 disconnect cause </H2>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

	print("<table frame=border align=\"center\">");
	print("<tr><td>Destination</td><td> Q931 &nbsp;</td><td>Cause &nbsp;</td> <td> Number &nbsp;</td></tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$destination = pg_result($result, $li, 0);
	$count = pg_result($result, $li, 1);
	$cause = pg_result($result, $li, 2);
	$qcause = pg_result($result, $li, 3);

	print("<tr><td>$destination</td><td> $cause &nbsp; </td><td> $qcause &nbsp;</td> <td> $count &nbsp;</td></tr>");

	}

	print("</table >");

	print("<p></p>");
	print("<p></p>");

pg_close($connection);
include "../local/tail.php";

?>

