
<html>
<head></head>
<body>
<?php
include "local/connect.php";

$query = "SELECT disconnecttime, callingstationid, calledstationid, prefix, duration/100, 
        cost, terminatecause, tariffdesc 
        from voipcall 
        where disconnecttime::timestamp between (current_date - 15) and (current_date - 6)
        order by disconnecttime desc";

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");

$rows = pg_num_rows($result);

print("<H1>Call termination last week  (week ending 7 days ago) <br/> </H1>");
print("<H1> ($rows calls), most recent first <br> </H1>");

echo '<table align="centre"/>';

echo '<tr/><td/>   Date and Time ------------    &nbsp; ' ;
echo '<td/>        Caller ----------   &nbsp;  ' ;
echo '<td/>        Called ---------   &nbsp;  ' ;
echo '<td/>        Prefix   &nbsp;  ' ;
echo '<td/>        Tariff  &nbsp;  ' ;
echo '<td/>        Duration   &nbsp;  ' ;
echo '<td/>        Cost   &nbsp;  ' ;
echo '<td/>        Cause   &nbsp;  <//tr/>' ;

for ($li=0; $li < $rows; $li+=1)
	{
#	$time = substr(pg_result($result, $li, 0), 0, 12);
	$time = pg_result($result, $li, 0);
	$origin = pg_result($result, $li, 1);
	$carrier = pg_result($result, $li, 2);
	$prefix = pg_result($result, $li, 3);
	$duration = number_format(pg_result($result, $li, 4), 2);
	$cost = number_format(pg_result($result, $li, 5), 2);
	$cause = pg_result($result, $li, 6);
	$tariff = pg_result($result, $li, 7);

	print("\n<tr/> <td/>  $time $sep ");
	print("\n<td/>  $origin $sep ");
	print("\n<td/>  $carrier $sep ");
	print("\n<td/>  $prefix $sep ");
	print("\n<td/>  $tariff $sep ");
	print("\n<td/>  $duration $sep ");
	print("\n<td/>  $cost $sep ");
	print("\n<td/>  $cause  <//tr /> ");

	}
	print("<//table /> \n");
pg_close($connection);

?>
</body>
</html>
