<?php
include "heading.html";

// These choices correspond to the tables in the schema
// except voipcalls, which is in the root folder. 
// Each option moves to the corresponding folder and reloads everything. 
// This same instance of the menu applies in all cases. 
print("<table align=center border=none ><tr>");
//print("<td>  <A HREF=\"/index.html\" TARGET=\"main_window\">Home</A> </td>");
print("<td>  <A HREF=\"/index.html\" TARGET=\"_top\">Home</A> </td>");
print("<td>  <A HREF=\"/accounts\" TARGET=\"_top\">Accounts</A> </td>");
print("<td>  <A HREF=\"/calldetails\" TARGET=\"_top\">Call Details</A> </td>");
print("<td>  <A HREF=\"/costs\" TARGET=\"_top\">Costs</A> </td>");
print("<td>  <A HREF=\"/qa\" TARGET=\"_top\">QA</A> </td>");
print("<td>  <A HREF=\"/misc\" TARGET=\"_top\">Tariff Misc</A> </td>");
print("<td>  <A HREF=\"/tariffs\" TARGET=\"_top\">Tariffs</A> </td>");
print("<td>  <A HREF=\"/users\" TARGET=\"_top\">Users</A> </td>");
print("</tr>");

?>
