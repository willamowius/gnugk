
<html>
<head></head>
<body>
<?php

include "../local/connect.php";

$pfx = $_POST['prefix']  ;
$prefix = $_POST['prefix'] . "%" ;

print("Rate data calculated on $edate <br><br>");

$query = "SELECT distinct carrier, prefix, destination, rate 
	from termination where prefix like '$prefix' order by prefix, carrier ;";

print("<H1 align =\"center\"/>Rates offered to $pfx* <br> </H1>");
	print("<p></p>");
	print("<p></p>");

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr><td>Carrier &nbsp;<td>Prefix &nbsp; <td> Destination &nbsp;  ");
	print("<td>Eurocents </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$carrier = pg_result($result, $li, 0);
	$prefix = pg_result($result, $li, 1);
	$destination = pg_result($result, $li, 2);
	$rate = number_format(pg_result($result, $li, 3),  3);

	print("<tr><td>$carrier &nbsp;<td>$prefix &nbsp; <td> $destination &nbsp;  ");
	print("<td> &nbsp; $rate  </tr> ");
	}
	print("</table>");

	print("<p></p>");
	print("<p></p>");
	print("<p></p>");

pg_close($connection);

?>
</body>
</html>
