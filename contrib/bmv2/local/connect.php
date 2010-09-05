<?php
$host = "192.168.1.1";
$user = "gkradius";
$pass = "d1ameter";
$db = "voipdb";
$connection = pg_connect("host=$host dbname=$db user=$user password = $pass");
if (!$connection) 
	{
	die("<br>  Cannot connect to the database. <br>  ");
	}

?>

