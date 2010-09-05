<?php
include "../local/top.php";

echo '<h1>Misc Tariff related tables</h1>';
echo '<p>(voiptariffgrp voiptariffdst voiptariffsel )</p>';

echo '<table align="centre">';
echo '<tr><td colspan="2">Voiptariffdst - tariff destinations (prefix).   &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">
   Pricing and billing information, which change frequently, are held separate from rarely changing prefix information. A special 
   prefix &quot;PC&quot; can be used to describe H.323 ID calls (to alias names beginning with non-digit characters).</td></tr>' ;

echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td> Destination ID &nbsp; </td> <td></td></tr>' ;
echo '<tr><td> Active   &nbsp;  </td><td>If not true, destination is blocked (eg premium rate)</td></tr>' ;
echo '<tr><td> Prefix   &nbsp;  </td><td>Prefix to which rate applies</td></tr>' ;
echo '<tr><td> Description   &nbsp; </td> <td>Destination name</td></tr>' ;
echo '<tr><td> Exact Match   &nbsp; </td> <td>If true, the destination is an H323 ID</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;


echo '<tr><td colspan="2">voiptariffgrp - Tariff Group </td></tr>' ;
echo '<tr><td colspan="2">A tariff group optionally holds one or more 
   tariffs. 
   ' ;
echo '</td></tr>' ;

echo '<tr><td>Group ID  &nbsp; </td> <td></td></tr>' ;
echo '<tr><td>Priority    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td>Description    &nbsp; </td> <td>Name of group</td></tr>' ;

echo '<tr><td colspan="2">voiptariffsel - tariff Selection' ;
echo '</td></tr>' ;
echo '<tr><td colspan="2"> voiptariffsel binds a tariff group to an account&nbsp;</td></tr>' ;
echo '<tr><td>Sel ID    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td>Group ID   &nbsp; </td> <td>Group ID</td></tr>' ;
echo '<tr><td>Account    &nbsp; </td> <td>Account ID</td></tr>' ;

echo '<tr><td colspan="2">The group affects the tariff priority during tariff selection:  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">If two or more tariffs apply to the same destination, a 
   tariff that belongs to a group associated with the particular account has priority 
   over the default tariff.  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '</td></tr>' ;

echo '</table > \n';

include "../local/tail.php";
?>

