
<?php

function list_details($result)
{

	$rows = pg_num_rows($result);

	print("<table frame=border align=\"center\">");
	print("<tr>  ");
	print("<td>ID &nbsp; </td> ");
	print("<td>Time &nbsp; </td> ");
	print("<td>Account &nbsp; </td> ");
	print("<td>H323 ID &nbsp; </td> ");
	print("<td>Calling &nbsp; </td> ");
	print("<td>Called &nbsp; </td> ");
	print("<td>Prefix &nbsp; </td> ");
	print("<td>Tariff &nbsp; </td> ");
	print("<td>Connected &nbsp; </td> ");
	print("<td>Disconnected &nbsp; </td> ");
	print("<td>Duration &nbsp; </td> ");
	print("<td>Cost &nbsp; </td> ");
//	print("<td> &nbsp; </td> ");
	print(" </tr> ");

	for($li = 0; $li < $rows ; $li = $li+1) 
	{
	$id = pg_result($result, $li, 0);
	$time = pg_result($result, $li, 1);
	$acct = pg_result($result, $li, 2);
	$h323 = pg_result($result, $li, 3);
	$calling = pg_result($result, $li, 4);
	$called = pg_result($result, $li, 5);
	$prefix = pg_result($result, $li, 6);
	$tariff = pg_result($result, $li, 7);
	$connected = pg_result($result, $li, 8);
	$disconnected = pg_result($result, $li, 9);
	$duration = pg_result($result, $li, 10);
	$cost = pg_result($result, $li, 11);

	print("<tr>  ");
	print("<td>$id &nbsp; </td> ");
	print("<td>$time &nbsp; </td> ");
	print("<td>$acct &nbsp; </td> ");
	print("<td>$h323 &nbsp; </td> ");
	print("<td>$calling &nbsp; </td> ");
	print("<td>$called &nbsp; </td> ");
	print("<td>$prefix &nbsp; </td> ");
	print("<td>$tariff &nbsp; </td> ");
	print("<td>$connected &nbsp; </td> ");
	print("<td>$disconnected &nbsp; </td> ");
	print("<td>$duration &nbsp; </td> ");
	print("<td>$cost &nbsp; </td> ");
	print(" </tr> ");
	}
	print("</table>");

}

?>

