
<?php
include "../local/top.php";
include "../local/connect.php";
include "../lib/display-cdr.php";


print("<H1 align =\"center\"/>Calls today and yesterday <br> </H1>");


$query = "SELECT id, acctstarttime, accountid, h323id,  
	callingstationid, calledstationid, prefix, tariffdesc, 
	setuptime, terminatecause, duration/60, cost
     	FROM voipcall where acctstarttime::timestamp > (current_date - 1)
        ORDER BY acctstarttime DESC";
	$result = pg_query($connection, $query) 
		or die(" Unable to query the database ");

list_details($result);



pg_close($connection);
include "../local/tail.php";
?>

