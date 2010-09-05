<?php
include "../local/top.php";

echo '<h1>A (voip)</h1>';
echo '<table align="centre">';

echo '<tr><td colspan="2"> voiptariff - a tariff associates a destination  
   with pricing and billing information. &nbsp;</td></tr>' ;
echo '<tr><td>    nbsp; </td> <td></td></tr>' ;
echo '<tr><td colspan="2">Tariffs can be default, or belong to a particular tariff group. 
   The tariff group is typically associated with a carrier, but some carriers offer
   more than one group - eg regular and premium.  &nbsp;</td></tr>' ;
echo '<tr><td>    nbsp; </td> <td></td></tr>' ;

echo '<tr><td colspan="2">    There are two tariff types: regular and "terminating".  
   Regular tariffs are to give pricing information
   for origination, and apply to a caller.  &nbsp;</td></tr>' ;

echo '<tr><td>    nbsp; </td> <td></td></tr>' ;
echo '<tr><td colspan="2"> Terminating tariffs apply to a terminating gateway. Terminating gateways
   are identified by their IP addresses (voipuser.framedip) or, for tariffs with exactmatch 
	flag set, H.323 ID (voipuser.h323id). &nbsp;</td></tr>' ;

echo '<tr><td>    nbsp; </td> <td></td></tr>' ;
echo '<tr><td colspan="2"> If you need terminations accounts, you create two tariffs per destination 
 - one for origination and and the second for termination. &nbsp;</td></tr>' ;

echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td>    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td>    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td>    &nbsp;  </td><td></td></tr>' ;
echo '<tr><td>    &nbsp;  </td><td></td></tr>' ;
echo '<tr><td>    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '</table > \n';

include "../local/tail.php";
?>

