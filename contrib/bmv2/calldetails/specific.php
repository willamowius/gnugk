
<?php
include "../local/top.php";
include "../local/connect.php";
include "../lib/dropdown.php";

print_r($_GET);

print "<h1>Choose your selection criterion</h1>";

print ("<form method=post action=\"specific2.php\">");
print "<table align=center>";
print ("<td><tr>&nbsp;");print ("</td></tr>");
print ("<td><tr>&nbsp;");print ("</td></tr>");
print ("<tr>");

if( isset($_GET['dest']) )
        {
//print "<br>Dest<br>";
        dropdown("Destination", voiptariffdst, "select" );        
        $clause = " and destination like  ";
        };

if (isset($_GET['acct']))
        {
//print "<br>Acct<br>";
        dropdown_desc("Account", voipaccount, "select", "id" );        
        $clause = " and accountid =  ";
        };

if (isset($_GET['user']))
        {
//print "<br>User<br>";
        dropdown_desc("User", voipuser, "select", "h323id" );        
        $clause = " and h323id =  ";

        };
print ("</td></tr>");
print ("<td><tr>&nbsp;");print ("</td></tr>");
print ("<td><tr>&nbsp;");print ("</td></tr>");
print "<input type=hidden name=\"clause\" value=\"$clause\" />";

print ("<tr><td><input type=submit>");
print ("</td></tr>");
print "</table>";
print "</form>";
pg_close($connection);
include "../local/tail.php";
?>

