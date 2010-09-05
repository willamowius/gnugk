
<?php
include "../local/top.php";
include "../local/connect.php";
include "../lib/display-cdr.php";

print_r($_POST);

$clause = $_POST['clause'];
$select = $_POST['select'];

print("<H1 align =\"center\"/>Calls today and yesterday <br> </H1>");


$query = "SELECT id, acctstarttime, accountid, h323id,  
	callingstationid, calledstationid, prefix, tariffdesc, 
	setuptime, terminatecause, duration/60, cost
     	FROM voipcall where acctstarttime::timestamp > (current_date - 1)
        $clause '$select'
        ORDER BY acctstarttime DESC";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database <br>") || $query ;

list_details($result);

pg_close($connection);
include "../local/tail.php";
?>

