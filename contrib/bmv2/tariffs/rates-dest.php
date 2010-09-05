
<html>
<head></head>
<body>
<?php

include "../local/connect.php";

$dst = $_POST['destination']  ;
$destination = $_POST['destination'] . "%" ;

//print("Rate data calculated on $edate <br><br>");

$query = "SELECT G.description, V.description, currencysym, price
	from voiptariff as v, voiptariffgrp as g
        where v.description like '$destination' and G.id = V.grpid
        order by G.description, grpid ;";

print("<H1 align =\"center\"/>Rates offered to $dst* <br> </H1>");
	print("<p></p>");
	print("<p></p>");

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr><td>Plan &nbsp;</td> <td> Destination &nbsp;</td>  ");
	print("<td>Rate</td> </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$plan = pg_result($result, $li, 0);
	$destination = pg_result($result, $li, 1);
	$currency = pg_result($result, $li, 2);
	$rate = number_format(pg_result($result, $li, 3),  3);

	print("<tr><td>$plan &nbsp;</td><td> $destination &nbsp;  </td>");
	print("<td> $currency &nbsp; $rate </td> </tr> ");
	}
	print("</table>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

pg_close($connection);

?>
</body>
</html>
