<?php
include "../local/top.php";

echo '<h1>Billing Manager for VoIP</h1>';
echo '<p>A web based user interface for Sqlbill.</p>';
echo '<p>&copy;2010, Andrew C Grillet. Released under GPL2</p>';
echo '<table align="centre">';

echo '<tr><td colspan="2">BMV provides read-only access to the Sqlbill tables.<br>
  It was created by Andrew Grillet, of Callgates Global.  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">It was originally used to provide calling card
  operator clients with a means to access records of their costs - ie what<br>
  they would need to pay in origination and termination costs.  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">In this context, a separate, (Radius based) platform is
  used by the card operator to compute his client charges (the money deducted from
  the calling cards). Separate platforms are used because the cost basis is different 
  in the two cases - ie the service providers do not bill on the same basis as the
  card operator does. The card operator may also use alternate service providers 
  with different tariff structures, while charging the card user on a fixed basis. 
 &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">Sqlbill comes with virtually no documentation. BMV has some
  help files which are intended to make it easier to understand what Sqlbill does, and
  how to use it. It is not impossible that the help files are wrong! If so, please correct
  them, and commit the fixes! Its GPL software so we can all benefit from your fixes!
 &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">The nature of BMV reflects its origins - the card operator 
 needs to know his costs, etc, but does not himself update the tables. I have
 no objection to anyone adding the functionality to update tables, but in my
 experience, there would need to be a significant security infrastructure in place
 before write access to tables is provided. Sqlbill does not support one at present.  
 &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td>    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '</table >';

include "../local/tail.php";
?>

