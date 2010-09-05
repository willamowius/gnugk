
<html>
<head></head>
<body>
<?php
include "../local/connect.php";

$query = "SELECT * from gateways ;";

print("<H1 align =\"center\"/>Callgates gateway details <br/> </H1/>");
	print("<p/></p/>");
	print("<p/></p/>");

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");

	$rows = pg_num_rows($result);

	print("<table align=\"center\"/>");
	print("<tr/><td/>Name &nbsp; <td/> IP Address &nbsp; <td/> Carrier &nbsp;<td/> Hardware &nbsp; <//tr/> ");
	print("<tr></tr>");
	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$name = pg_result($result, $li, 0);
	$address = pg_result($result, $li, 1);
	$carrier = pg_result($result, $li, 2);
	$type = pg_result($result, $li, 3);
	print("<tr/><td/>$name &nbsp; <td/> $address &nbsp; <td/> $carrier &nbsp;<td/> $type &nbsp; </tr/> ");
	}
	print("</table/>");

pg_close($connection);

?>
</body>
</html>
