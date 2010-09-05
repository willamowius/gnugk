<?php
include "../local/top.php";
include "../local/connect.php";

if(isset($_GET['all']))
	$sel = " ";;

if(isset($_GET['disabled']))
	$sel = " where disabled = 't' ";;

if(isset($_GET['active']))
	$sel = " where disabled != 't' ";;

$query = "SELECT id, h323id, accountid, checkh323id, chappassword, allowedaliases, 
	assignaliases, framedip, terminating, nasaddress, disabled  
	from voipuser " . $sel . " order by accountid";

$result = pg_query($connection, $query) 
	or die(" Unable to query the users database ");


$rows = pg_num_rows($result);
print("<H1>Users (endpoints) </H1>");
//print("<p>$rows endpoints <br> </p>");

echo '<table align="centre">';

echo '<tr><td>   User ID &nbsp; </td> ' ;
echo '<td>        h323id  &nbsp; </td> ' ;
echo '<td>        Accountid  &nbsp; </td> ' ;
echo '<td>        Checkh323id &nbsp;  </td>' ;
echo '<td>        Chap Passwd &nbsp;  </td>' ;
echo '<td>        Allowed Alias &nbsp;  </td>' ;
echo '<td>        Assign Alias &nbsp;  </td>' ;
echo '<td>        Framed IP &nbsp;  </td>' ;
echo '<td>        Terminating &nbsp;  </td>' ;
echo '<td>        Nas Address  &nbsp;  </td>' ;
if(isset($_GET['all']))
   echo '<td>        Disabled &nbsp; </td> ' ;
echo '</tr>' ;

for ($li=0; $li < $rows; $li+=1)
	{
	$id = pg_result($result, $li, 0);
	$h323 = pg_result($result, $li, 1);
	$account = pg_result($result, $li, 2);
	$check = pg_result($result, $li, 3);
	$chap = pg_result($result, $li, 4);
	$allowed = pg_result($result, $li, 5);
	$assign = pg_result($result, $li, 6);
	$framed = pg_result($result, $li, 7);
	$terminating = pg_result($result, $li, 8);
	$nas = pg_result($result, $li, 9);
	$disabled = pg_result($result, $li, 10);
	print("\n<tr> <td>  $id </td> ");
	print("\n<td>  $h323 </td> ");
	print("\n<td>  $account </td> ");
	print("\n<td>  $check </td> ");
	print("\n<td>  $chap </td> ");
	print("\n<td>  $allowed </td> ");
	print("\n<td>  $assign </td> ");
	print("\n<td>  $framed </td> ");
	print("\n<td>  $terminating </td> ");
	print("\n<td>  $nas </td> ");
   if(isset($_GET['all']))
  	print("\n<td>  $disabled </td>  ");
	print(" </tr > ");
	}
	print("</table > \n");
pg_close($connection);

include "../local/tail.php";
?>

