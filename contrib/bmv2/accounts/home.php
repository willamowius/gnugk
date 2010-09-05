<?php
include "../local/top.php";
include "../local/connect.php";

if(isset($_GET['all']))
	$sel = " ";;
if(isset($_GET['low']))
	$sel = " where (balancelimit - balance) < '100' ";;
if(isset($_GET['active']))
	$sel = " where disabled = 'f' ";;
if(isset($_GET['disabled']))
	$sel = " where disabled = 't' ";;

$disabled = $_GET['disabled'];
$active = $_GET['active'];

$query = "SELECT id, created, closed, disabled, balance, balancelimit, currencysym 
	from voipaccount " . $sel . " order by id";

$result = pg_query($connection, $query) 
	or die(" Unable to query the accounts database ");


$rows = pg_num_rows($result);
print("<H1>Accounts  (business units) </H1>");
//print("<p>$rows accounts on record <br> </p>");

echo '<table align="centre">';

echo '<tr><td>    ID &nbsp; </td> ' ;
echo '<td>        Created  &nbsp; </td> ' ;
echo '<td>        Closed  &nbsp; </td> ' ;
echo '<td>        Balance &nbsp;  </td>' ;
echo '<td>        Limit &nbsp;  </td>' ;
echo '<td>        Disabled  &nbsp; </td> </tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$id = pg_result($result, $li, 0);
	$created = pg_result($result, $li, 1);
	$closed = pg_result($result, $li, 2);
	$disabled = pg_result($result, $li, 3);
	$balance = number_format(pg_result($result, $li, 4), 2);
	$limit = number_format(pg_result($result, $li, 5), 2);
	$currency = pg_result($result, $li, 6);
	print("\n<tr> <td>  $id </td> ");
	print("\n<td>  $created </td> ");
	print("\n<td>  $closed </td> ");
	print("\n<td> $currency  $balance </td> ");
	print("\n<td>  $limit </td> ");
	print("\n<td>  $disabled </td> </tr > ");

	}
	print("</table > \n");
pg_close($connection);

include "../local/tail.php";
?>

