<?php
include "heading.html";

// These choices correspond to the tables in the schema
// except voipcalls, which is in the root folder. 
// Each option moves to the corresponding folder and reloads everything. 
// This same instance of the menu applies in all cases. 
print("<table align=center border ><tr>");
print("<td>  <A HREF=\"/index.html\" TARGET=\"main_window\">Home</A> </td>");
print("<td>  <A HREF=\"accounts\" TARGET=\"main_window\">Accounts</A> </td>");
print("<td>  <A HREF=\"attrib\" TARGET=\"main_window\">Radius Attributes</A> </td>");
print("<td>  <A HREF=\"calldetails\" TARGET=\"main_window\">Call Details</A> </td>");
print("<td>  <A HREF=\"costs\" TARGET=\"main_window\">Costs</A> </td>");
print("<td>  <A HREF=\"qa\" TARGET=\"main_window\">QA</A> </td>");
print("<td>  <A HREF=\"misc\" TARGET=\"main_window\">Tariff Misc</A> </td>");
print("<td>  <A HREF=\"tariffs\" TARGET=\"main_window\">Tariffs</A> </td>");
print("<td>  <A HREF=\"users\" TARGET=\"main_window\">Users</A> </td>");
//print("<td>  <A HREF="../index.html" TARGET="main_window">Exit</A> </td>");
print("</tr>");

?>
