
<html>
<head></head>
<body>
<?php
include "../local/connect.php";

$car = $_POST['carrier'];
$carrier = $_POST['carrier'] . "%";

print("Rate data calculated on $edate <br><br>");

$query = "SELECT distinct prefix, destination, rate 
	from termination where carrier like '$carrier' order by prefix ;";

print("<H1 align =\"center\"/>Rates offered by $car* <br> </H1>");
	print("<p></p>");
	print("<p></p>");

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");


	$rows = pg_num_rows($result);


	print("<table frame=border align=\"center\">");
	print("<tr><td>Prefix &nbsp; <td> Destination &nbsp;  ");
	print("<td>Eurocents </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$prefix = pg_result($result, $li, 0);
	$destination = pg_result($result, $li, 1);
	$rate = number_format(pg_result($result, $li, 2),  3);

	print("<tr><td>$prefix &nbsp; <td> $destination &nbsp;  ");
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
