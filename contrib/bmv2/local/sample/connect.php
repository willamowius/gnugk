<?php
$host = "localhost";
$user = "gkradius";
$pass = "hax0rs";
$db = "voipdb";
$connection = pg_connect("host=$host dbname=$db user=$user password = $pass");
if (!$connection) 
	{
	die(" <br> Cannot find the database! Mbr>  ");
	}
?>

