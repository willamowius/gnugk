
<?php
include "../local/top.php";
include "../local/connect.php";

$start = mktime(0,0,0, $_POST['smonth'], $_POST['sday'], $_POST['syear']);
$end = mktime(23,59,59, $_POST['emonth'], $_POST['eday'], $_POST['eyear']);

$sdate = date("D j M Y H:i:s", $start);
$edate =  date("D j M Y H:i:s", $end);

$query = "SELECT tariffdesc , COUNT(*) ,
		ROUND(SUM(COALESCE(duration, 0))::NUMERIC / 60::NUMERIC, 1),
		SUM(COALESCE(cost, 0)), currencysym 
	FROM voipcall
	WHERE connecttime IS NOT NULL AND currencysym IS NOT NULL AND tariffdesc IS NOT NULL
		AND acctstarttime between '$sdate' and '$edate' 
	GROUP BY tariffdesc, currencysym
	ORDER BY tariffdesc ,  currencysym";

$result = pg_query($connection, $query) 
	or die(" Unable to query the accounts database ");


$rows = pg_num_rows($result);
print("<H1>Costs from $sdate to $edate  </H1>");

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
	print("\n<tr> <td>  $destination </td> ");
	print("\n <td>  $calls </td> ");
	print("\n <td>  $minutes </td> ");
	print("\n <td>  $currency  $cost </td> ");
	print("\n<td>  $disabled </td> </tr > ");
	}
	print("</table > \n");
pg_close($connection);

include "../local/tail.php";
?>


