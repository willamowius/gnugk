<?php
include "../local/top.php";

echo '<h1>Call Detail Records (voipcalls)</h1>';
echo '<table align="centre">';

echo '<tr><td colspan="2">This is the table keeping track of all calls  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">
 &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td>ID   &nbsp; </td> <td>Unique ID of CDR</td></tr>' ;
echo '<tr><td>Account ID    &nbsp; </td> <td>Who pays/is paid</td></tr>' ;
echo '<tr><td>H323ID    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td>Acctsession ID    &nbsp;  </td><td>Unique ID of call</td></tr>' ;
echo '<tr><td>H323conf ID    &nbsp;  </td><td></td></tr>' ;
echo '<tr><td>Gk IP    &nbsp; </td> <td>Gatekeeper IP</td></tr>' ;
echo '<tr><td>Gk ID    &nbsp; </td> <td>Gatekeeper ID</td></tr>' ;
echo '<tr><td>Callingstation IP    &nbsp; </td> <td>Originator IP</td></tr>' ;
echo '<tr><td>Callingstation ID    &nbsp; </td> <td>Originator ID</td></tr>' ;
echo '<tr><td>Calledstation IP    &nbsp;  </td><td>Terminator IP</td></tr>' ;
echo '<tr><td>Calledstation ID    &nbsp;  </td><td>Terminator ID</td></tr>' ;
echo '<tr><td>Setup time    &nbsp; </td> <td>Time call was setup</td></tr>' ;
echo '<tr><td>Connect time    &nbsp; </td> <td>Time call was connected</td></tr>' ;
echo '<tr><td>Disconnect time    &nbsp; </td> <td>Time call ended</td></tr>' ;
echo '<tr><td>Terminate Cause    &nbsp; </td> <td>Reason call ended</td></tr>' ;
echo '<tr><td>Duration    &nbsp;  </td><td>Total duration of call</td></tr>' ;
echo '<tr><td>Cost    &nbsp;  </td><td>Total cost of call</td></tr>' ;
echo '<tr><td>Price    &nbsp; </td> <td>cost per minute???</td></tr>' ;
echo '<tr><td>CurrencySym    &nbsp; </td> <td>Currency used</td></tr>' ;
echo '<tr><td>Tariff Desc    &nbsp; </td> <td>Name of tariff</td></tr>' ;
echo '<tr><td>Initial Increment  &nbsp; </td> <td>Length of initial charge unit</td></tr>' ;
echo '<tr><td>Regular Increment  &nbsp;  </td><td>Length of further charge unit</td></tr>' ;
echo '<tr><td>Grace Period    &nbsp;  </td><td>Minimum duraiton for chargeable call</td></tr>' ;
echo '<tr><td>Acct Start time &nbsp; </td> <td>Time accounting commenced</td></tr>' ;
echo '<tr><td>Acct Start delay &nbsp; </td> <td>Delay till start was recorded</td></tr>' ;
echo '<tr><td>Acct Update time &nbsp;  </td><td>Time accounting last updated</td></tr>' ;
echo '<tr><td>Acct Stop time  &nbsp;  </td><td>Time accounting ceased</td></tr>' ;
echo '<tr><td>Acct Stop delay &nbsp; </td> <td>Delay till stop was recorded</td></tr>' ;
echo '<tr><td>Prefix    &nbsp; </td> <td>Prefix used for tariff</td></tr>' ;
echo '<tr><td>    &nbsp;  </td><td></td></tr>' ;
echo '<tr><td>    &nbsp; </td> <td></td></tr>' ;
echo '<tr><td colspan="2">Accounting data is maintained from this table using triggers.  &nbsp;</td></tr>' ;
echo '</table > \n';

include "../local/tail.php";
?>

