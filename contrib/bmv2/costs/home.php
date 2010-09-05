<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT tariffdesc, COUNT(*) ,
		ROUND(SUM(COALESCE(duration, 0))::NUMERIC / 60::NUMERIC, 1) ,
		SUM(COALESCE(cost, 0)), currencysym 
	FROM voipcall
	WHERE connecttime IS NOT NULL AND currencysym IS NOT NULL AND tariffdesc IS NOT NULL
	 	AND (acctstarttime >= (current_date - '1 day'::INTERVAL))
	GROUP BY tariffdesc, currencysym
	ORDER BY 4 DESC, 5 DESC";


$result = pg_query($connection, $query) 
	or die(" Unable to query the accounts database ");


$rows = pg_num_rows($result);
print("<H1>Costs for today and yesterday  </H1>");

echo '<table align="centre">';

echo '<tr><td>    Destination &nbsp; </td> ' ;
echo '<td>        Calls  &nbsp; </td> ' ;
echo '<td>        Minutes  &nbsp; </td> ' ;
echo '<td>        Cost &nbsp; </td> </tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$destination = pg_result($result, $li, 0);
	$calls = pg_result($result, $li, 1);
	$minutes = pg_result($result, $li, 2);
	$cost = pg_result($result, $li, 3);
	$currency = pg_result($result, $li, 4);
	print("<tr> <td>  $destination </td> ");
	print(" <td>  $calls </td> ");
	print(" <td>  $minutes </td> ");
	print(" <td>  $currency  $cost </td> ");
	print(" <td>  $disabled </td> </tr > ");
	}
	print("</table > \n");
pg_close($connection);

include "../local/tail.php";
?>

