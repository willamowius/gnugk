<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT id, grpid, accountid 
	from voiptariffsel order by id ;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the tariff sel database ");

$rows = pg_num_rows($result);
print("<H1>Tariff Selection <br> </H1>");

echo '<table align="centre">';

echo '<tr><td>    Selection ID &nbsp; </td> ' ;
echo '<td>        Group ID  &nbsp; </td> ' ;
echo '<td>        Account ID &nbsp;  </td> </tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$id = pg_result($result, $li, 0);
	$grp = pg_result($result, $li, 1);
	$account = pg_result($result, $li, 3);
	print("\n<tr> <td>  $id </td> ");
	print("\n<td>  $grp </td> ");
	print("\n<td>  $account </td> </tr > ");

	}
	print("</table > \n");
pg_close($connection);

include "../local/top.php";
?>

