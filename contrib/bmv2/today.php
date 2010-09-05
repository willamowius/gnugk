
<html>
<head></head>
<body>
<?php
include "local/connect.php";

$query = "SELECT acctstarttime, callingstationid, calledstationid, prefix, 
        duration/60, cost, terminatecause, tariffdesc 
        from voipcall where acctstarttime::timestamp > current_date 
        order by acctstarttime;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");
$sep = " ";

$rows = pg_num_rows($result);
print("<H1>Call termination today ($rows calls) <br> </H1>");

echo '<table align="centre">';

echo '<tr><td>    Date and Time ------------    &nbsp; ' ;
echo '<td>        Caller ----------   &nbsp;  ' ;
echo '<td>        Called -------   &nbsp;  ' ;
echo '<td>        Prefix   &nbsp;  ' ;
echo '<td>        Tariff  &nbsp;  ' ;
echo '<td>        Duration (mins)  &nbsp;  ' ;
echo '<td>        Cost (Eur)  &nbsp;  ' ;
echo '<td>        Cause   &nbsp;  </tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
#	$time = substr(pg_result($result, $li, 0), 0, 13);
	$time = pg_result($result, $li, 0);
	$caller = pg_result($result, $li, 1);
	$called = pg_result($result, $li, 2);
	$prefix = pg_result($result, $li, 3);
	$duration = number_format(pg_result($result, $li, 4), 2);
	$cost = number_format(pg_result($result, $li, 5), 2);
	$cause = pg_result($result, $li, 6);
	$desc = pg_result($result, $li, 7);

	print("\n<tr> <td>  $time $sep ");
	print("\n<td>  $caller $sep ");
	print("\n<td>  $called $sep ");
	print("\n<td>  $prefix $sep ");
	print("\n<td>  $desc $sep ");
	print("\n<td>  $duration $sep ");
	print("\n<td>  $cost $sep ");
	print("\n<td>  $cause  </tr > ");

	}
	print("</table > \n");
pg_close($connection);

?>
</body>
</html>
