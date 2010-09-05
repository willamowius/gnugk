<?php
include "../local/top.php";
print("<h2>Accounts</h2>");
 
print("<HR color=\"red\" size=\"10\">"); 
print("<ul><li />  <A HREF=\"home.php?all\" TARGET=\"right_window\" >All accounts</A> "); 
print("<li />  <A HREF=\"home.php?active\" TARGET=\"right_window\" >Active Accounts</A> "); 
print("<li />  <A HREF=\"home.php?disabled\" TARGET=\"right_window\" >Disabled</A> "); 
print("<li /> <A HREF=\"home.php?low\" TARGET=\"right_window\" >Low Balance </A> "); 
print("<li /> <A HREF=\"help.php?low\" TARGET=\"right_window\" >Help </A> "); 

print("<li />  </ul>"); 

include "../local/tail.php";
?>
