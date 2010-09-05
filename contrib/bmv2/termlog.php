
<html>
<head></head>
<body>
<?php
include "local/connect.php";

$query = "SELECT disconnecttime, callingstationid, calledstationid, duration, cost, 
        terminatecause, prefix, tariffdesc 
        from voipcall 
        order by acctstarttime desc ;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");


$rows = pg_num_rows($result);
echo  '<H1 align=center>The complete termination log: </H1>';

echo '<table align="centre"/>';

echo '<tr/><td/> Date and Time ------------- &nbsp; </td>' ;
echo '<td/>        Caller   &nbsp;  </td>' ;
echo '<td/>        Called   &nbsp;  </td>' ;
echo '<td/>        Prefix   &nbsp;  </td>' ;
echo '<td/>        Tariff   &nbsp;  </td>' ;
echo '<td/>        Minutes &nbsp;  </td>' ;
echo '<td/>        Cost &nbsp;  </td>' ;
echo '<td/>        Cause    &nbsp;  </td></tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$time = pg_result($result, $li, 0);
	$origin = pg_result($result, $li, 1);
	$carrier = pg_result($result, $li, 2);
	$duration = pg_result($result, $li, 3);
	$cost = pg_result($result, $li, 4);
	$cause = pg_result($result, $li, 5);
	$prefix = pg_result($result, $li, 6);
	$tariff = pg_result($result, $li, 7);

	print("\n<tr/> <td/>  $time  ");
	print("\n<td/>  $origin  ");
	print("\n<td/>  $carrier  ");
	print("\n<td/>  $prefix  ");
	print("\n<td/>  $tariff  ");
	print("\n<td/>  $duration  ");
	print("\n<td/>  $cost  ");
	print("\n<td/>  $cause  </tr > ");

	}
	print("</table > ");
pg_close($connection);

?>
</body>
</html>
