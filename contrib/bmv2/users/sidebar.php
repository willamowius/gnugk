<?php
include "../local/top.php";
print("<h2>Users (Endpoints)</h2>");
 
print("<HR color=\"red\" size=\"10\">"); 
print("<ul><li />  <A HREF=\"home.php?all\" TARGET=\"right_window\" >All endpoints</A> "); 
print("<li />  <A HREF=\"home.php?active\" TARGET=\"right_window\" >Active endpoints</A> "); 
print("<li />  <A HREF=\"home.php?disabled\" TARGET=\"right_window\" >Disabled endpoints</A> "); 
print("<li />  </ul>"); 

print("<ul><li />  <A HREF=\"originate.php?all\" TARGET=\"right_window\" >All originators</A> "); 
print("<li />  <A HREF=\"originate.php?active\" TARGET=\"right_window\" >Active  originators</A> "); 
print("<li />  </ul>"); 

print("<ul><li />  <A HREF=\"terminate.php?all\" TARGET=\"right_window\" >All terminators</A> "); 
print("<li />  <A HREF=\"terminate.php?active\" TARGET=\"right_window\" >Active terminators</A> "); 

print("<li />  </ul>"); 
print("<ul><li />  <A HREF=\"help.php\" TARGET=\"right_window\" >Help</A> "); 

print("<li />  </ul>"); 

include "../local/tail.php";
?>
