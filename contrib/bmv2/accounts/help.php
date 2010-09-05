<?php
include "../local/top.php";

echo '<h1>Accounts (voipaccount)</h1>';
echo '<table align="centre">';

echo '<tr><td colspan="2">An account is a business unit and may have several &quot;users&quot; (endpoints). &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">The account records the current balance and prepaid/postpaid balance limit.
 &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td>    ID&nbsp; </td> <td>Account ID</td></tr>' ;
echo '<tr><td>        Created  &nbsp; </td> <td>Date created</td></tr>' ;
echo '<tr><td>        Closed  &nbsp; </td> <td>Date Closed (Null if open)</td></tr>' ;
echo '<tr><td>        Balance &nbsp;  </td><td>Current Balance</td></tr>' ;
echo '<tr><td>        Limit &nbsp;  </td><td>Minimum balance required to make a call </td></tr>' ;
echo '<tr><td>        Disabled  &nbsp; </td> <td>If true, all endpoints of the account are blocked.</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">Limit is normally 0 for terminating services. It is typically about 0.15 to 0.25 for
	calling cards, depending on currency.   &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '</table > \n';

include "../local/tail.php";
?>

