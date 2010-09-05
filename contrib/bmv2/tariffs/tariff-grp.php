<?php
include "../local/top.php";
include "../local/connect.php";

$group = $_POST['group'] .'%' ;

print("Rate data for group $group calculated on $today <br><br>");

$query = "SELECT id, dstid, currencysym, initialincrement, regularincrement,
        graceperiod, description, price, terminating   
	from voiptariff where grpid like '$group'  and active = true order by dstid ;";

// print("<H1 align =\"center\"/>Rates offered by $car* <br> </H1>");
	print("<p></p>");
	print("<p></p>");

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr><td>ID &nbsp; </td>   ");
	print("<td> Destination&nbsp; </td>   ");
	print("<td> Tariff    &nbsp; </td>   ");
	print("<td> Initial&nbsp; </td>   ");
	print("<td> Increment &nbsp; </td>   ");
	print("<td> Grace &nbsp; </td>   ");
	print("<td> Description&nbsp; </td>   ");
	print("<td> Terminating&nbsp; </td>   ");
	print(" </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$id = pg_result($result, $li, 0);
	$destination = pg_result($result, $li, 1);
	$currency = pg_result($result, $li, 2);
	$initial = pg_result($result, $li, 3);
	$increment = pg_result($result, $li, 4);
	$grace = pg_result($result, $li, 5);
	$descr = pg_result($result, $li, 6);
	$price = number_format(pg_result($result, $li, 7),  3);
	$terminating = pg_result($result, $li, 8);

	print("<tr><td>$id &nbsp; <td> $destination &nbsp;  ");
	print("<td> $id &nbsp;   </tr> ");
	print("<td> $destination &nbsp;   </tr> ");
	print("<td> $currency &nbsp;%price &nbsp;   </tr> ");
	print("<td> $initial &nbsp; $increment &nbsp;  </tr> ");
	print("<td> $grace &nbsp;   </tr> ");
	print("<td> $descr &nbsp;   </tr> ");
	print("<td> $terminating &nbsp;   </tr> ");
	print("  </tr> ");
	}
	print("</table>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

pg_close($connection);

?>
</body>
</html>
