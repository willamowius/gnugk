<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT id, active, prefix, description, exactmatch 
	from voiptariffdst order by id ;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the tariffdst database ");


$rows = pg_num_rows($result);
print("<H1>Tariff Destinations <br> </H1>");

echo '<table align="centre">';

echo '<tr><td>    Destination ID &nbsp; </td> ' ;
echo '<td>        Active  &nbsp; </td> ' ;
echo '<td>        Prefix  &nbsp; </td> ' ;
echo '<td>        Description  &nbsp; </td> ' ;
echo '<td>        Exact Match &nbsp;  </td> </tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$id = pg_result($result, $li, 0);
	$active = pg_result($result, $li, 1);
	$prefix = pg_result($result, $li, 2);
	$descr = pg_result($result, $li, 3);
	$exact = pg_result($result, $li, 4);
	print("\n<tr> <td>  $id </td> ");
	print("\n<td>  $active </td> ");
	print("\n<td>  $prefix </td> ");
	print("\n<td>  $descr </td> ");
	print("\n<td>  $exact </td> </tr > ");

	}
	print("</table > \n");



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

