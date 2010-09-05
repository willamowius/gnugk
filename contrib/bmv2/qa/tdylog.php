
<html>
<head></head>
<body>
<?php
$host = "83.245.0.194";
$user = "www";
$pass = "passw0rd";
$db = "billing";
$sep = "&nbsp;  ";
$connection = pg_connect("host=$host dbname=$db user=$user password = $pass");
if (!$connection) 
	{
	die("  Cannot find the database  ");
	}
$query = "SELECT disconnect_time, origin, carrier, ani, duration/60, cost/100, disconnect_cause from call where disconnect_time::timestamp > current_date ;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");


$rows = pg_num_rows($result);
print("<H1>Call termination today ($rows calls) <br> </H1>");

echo '<table align="centre">';

echo '<tr><td>    Time ------------    &nbsp; ' ;
echo '<td>        Origin----------   &nbsp;  ' ;
echo '<td>        Carrier-------   &nbsp;  ' ;
echo '<td>        Destination----------   &nbsp;  ' ;
echo '<td>        Duration (mins)  &nbsp;  ' ;
echo '<td>        Cost (Eur)  &nbsp;  ' ;
echo '<td>        Cause   &nbsp;  </tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$time = substr(pg_result($result, $li, 0), 0, 13);
	$origin = pg_result($result, $li, 1);
	$carrier = pg_result($result, $li, 2);
	$destination = pg_result($result, $li, 3);
	$duration = number_format(pg_result($result, $li, 4), 2);
	$cost = number_format(pg_result($result, $li, 5), 2);
	$cause = pg_result($result, $li, 6);
	print("\n<tr> <td>  $time $sep ");
	print("\n<td>  $origin $sep ");
	print("\n<td>  $carrier $sep ");
	print("\n<td>  $destination $sep ");
	print("\n<td>  $duration $sep ");
	print("\n<td>  $cost $sep ");
	print("\n<td>  $cause  </tr > ");

	}
	print("</table > \n");
pg_close($connection);

?>
</body>
</html>
