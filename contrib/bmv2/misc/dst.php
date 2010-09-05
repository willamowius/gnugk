<?php
include "../local/top.php";
include "../local/connect.php";

$query = "SELECT id, active, prefix, description, exactmatch 
	from voiptariffdst order by id ;";

$result = pg_query($connection, $query) 
	or die(" Unable to query the tariffdst database ");


$rows = pg_num_rows($result);
print("<H1>Tariff Destinations <br> </H1>");
print("<p>(Destination to prefix mapping) </p>");

echo '<table align="centre">';

echo '<tr><td>    ID &nbsp; </td> ' ;
echo '<td>        Active  &nbsp; </td> ' ;
echo '<td>        Prefix  &nbsp; </td> ' ;
echo '<td>        Destination  &nbsp; </td> ' ;
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
pg_close($connection);

include "../local/top.php";
?>

