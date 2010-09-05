<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT id, priority, description
	from voiptariffgrp order by id ;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the attributes database ");


$rows = pg_num_rows($result);
print("<H1>Tariff Group  <br> </H1>");

echo '<table align="centre">';

echo '<tr><td>    Group ID &nbsp; </td> ' ;
echo '<td>        Priority  &nbsp; </td> ' ;
echo '<td>        Description  &nbsp;  </td> </tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$id = pg_result($result, $li, 0);
	$priority = pg_result($result, $li, 1);
	$descr = pg_result($result, $li, 2);
	print("\n<tr> <td>  $id </td> ");
	print("\n<td>  $priority </td> ");
	print("\n<td>  $descr </td> </tr > ");
	}
	print("</table > \n");
pg_close($connection);

include "../local/top.php";
?>

