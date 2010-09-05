<html>
<head></head>
<body>
<?php
include "../local/connect.php";

$query = "SELECT distinct u.country, u.region, 
		to_char((5 /u.rate::float), '999.9')
	from countries as c inner join ukrates as u 
	on u.country = c.country and c.popular = 1 order by country";
$result = pg_query($connection, $query) 
	or die("\nDatabase query had a fatal problem");

$rows = pg_num_rows($result);
echo "\nThe $rows most popular destinations are: <br/><br/><table align=\"center\"/>\n";

for ($li=0; $li < $rows; $li+=2)
	{
	$country = pg_result($result, $li, 0);
	$region = pg_result($result, $li, 1);
	$rate = pg_result($result, $li, 2);
	print("<tr/><td/>$country<//td/><td/>$region<//td/><td/> $rate<//td/> ");
        print("<td/>$sep <//td/>");
        if($li < ($rows - 1))
		{
	$country = pg_result($result, $li+1, 0);
	$region = pg_result($result, $li+1, 1);
	$rate = pg_result($result, $li+1, 2);
		}
	else
		{
	$country = "  ";
	$region = "  ";
	$rate = "   ";
		};
	print("<td/>$country<//td/><td/>$region<//td/><td/> $rate<//td/>  <//tr />\n");
	}
	print("<//table/>\n");
pg_close($connection);

?>
</body>
</html>
