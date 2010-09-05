<?php
include "../local/top.php";
print("<h2>Call Details</h2>");
 
print("<HR color=\"red\" size=\"10\"><ul>"); 
print("<li />  <A HREF=\"home.php\" TARGET=\"right_window\" >All</A> "); 
print("<li />  <A HREF=\"specific.php?dest\" TARGET=\"right_window\" >Specific Destination (name) </A> "); 
print("<li />  <A HREF=\"specific.php?acct\" TARGET=\"right_window\" >Specific account (Carrier)</A> "); 
print("<li />  <A HREF=\"specific.php?user\" TARGET=\"right_window\" >Specific user (Endpoint)</A> "); 
print("<li />  <A HREF=\"home.php\" TARGET=\"right_window\" >Home</A> "); 
print("<li />  <A HREF=\"help.php\" TARGET=\"right_window\" >Help</A> "); 
print("<li />  </ul>"); 

include "../local/tail.php";
?>
