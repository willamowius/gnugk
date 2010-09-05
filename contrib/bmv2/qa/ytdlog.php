
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
$query = "SELECT * from calls_yesterday ;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the database ");


$rows = pg_num_rows($result);
print("<H1/>Call termination yesterday ($rows calls) <br/> <//H1/>");

echo '<table align="centre"/>';

echo '<tr/><td/>   Time --------------    &nbsp; ' ;
echo '<td/>        Origin----------   &nbsp;  ' ;
echo '<td/>        Number----------   &nbsp;  ' ;
echo '<td/>        Duration   &nbsp;  ' ;
echo '<td/>        Cause   &nbsp;  <//tr/>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$time = substr(pg_result($result, $li, 0), 0, 16);
	$origin = pg_result($result, $li, 1);
	$number = pg_result($result, $li, 2);
	$duration = pg_result($result, $li, 3);
	$cause = pg_result($result, $li, 4);
	print("\n<tr/> <td/>  $time $sep ");
	print("\n<td/>  $origin $sep ");
	print("\n<td/>  $number $sep ");
	print("\n<td/>  $duration $sep ");
	print("\n<td/>  $cause  <//tr /> ");

	}
	print("<//table /> \n");
pg_close($connection);

?>
</body>
</html>
