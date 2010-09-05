<html>
<head></head>
<body>
<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT t.id, d.description, grpid, price, currencysym, initialincrement,
	regularincrement, t.description, graceperiod, terminating
	        from voiptariff as t, voiptariffdst as d 
                where t.dstid = d.id and t.active = 't' 
                order by t.description, grpid";
$result = pg_query($connection, $query) 
	or die("\nDatabase query had a fatal problem");

$rows = pg_num_rows($result);
echo "\n<br>There are $rows tariffs in the database. <br>";
echo "<br><table align=\"center\" />";

	print("<tr><td>ID</td><td>Tariff Group</td> <td>Destination</td>");
	print("<td>Initial</td><td> Regular</td> <td>Grace</td> ");
        print(" <td align=right>Price</td></tr>");

for ($li=0; $li < $rows; $li++)
	{
	$id = pg_result($result, $li, 0);
	$dst = pg_result($result, $li, 1);
	$grp = pg_result($result, $li, 2);
	$price = pg_result($result, $li, 3);
	$currency = pg_result($result, $li, 4);
	$initial = pg_result($result, $li, 5);
	$regular = pg_result($result, $li, 6);
	$desc = pg_result($result, $li, 7);
	$grace = pg_result($result, $li, 8);
	$term = pg_result($result, $li, 9);

	print("<tr><td>$id</td><td> $grp</td> <td>$dst</td>");
	print("<td>$initial</td><td>$regular</td><td>$grace</td> ");
        print("<td>$descr</td><td>$currency $price</td></tr>");
	}
	print("</table>\n");
pg_close($connection);

include "/local/tail.php";
?>

