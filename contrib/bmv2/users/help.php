<?php
include "../local/top.php";

echo '<h1>Users (endpoints)</h1>';
echo '<table align="centre">';

echo '<tr><td colspan="2">a voipuser corresponds to an H.323 endpoint. <br>Every user 
  (endpoint) must have an account.  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">The name &quot;user&quot; is misleading. These are endpoints. A business unit 
   &quot;account&quot; typically owns/manages several endpoints (users).  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">
 &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td>ID  &nbsp; </td> <td>Unique ID of the endpoint.</td></tr>' ;
echo '<tr><td>H.323 ID  &nbsp; </td> <td>The H.323 ID of the endpoint.</td></tr>' ;
echo '<tr><td>Account ID  &nbsp; </td> <td>The account (holder) responsible for the endpoint.</td></tr>' ;
echo '<tr><td>Chap Password &nbsp; </td> <td>Used with H.323 ID for H.235 authentication. </td></tr>' ;
echo '<tr><td>Allowed Aliases &nbsp; </td> <td>Aliases that the endpoint can register with. 
	(Its own H.323 ID is allowed by default.) </td></tr>' ;

echo '<tr><td>Assigned Aliases &nbsp;  </td><td>Aliases to be automatically assigned to an endpoint (inside RCF
     message).</td></tr>' ;
echo '<tr><td>    &nbsp;  </td><td>IP address restriction (NULL to ignore)</td></tr>' ;
echo '<tr><td>Terminating &nbsp; </td> <td>A flag that indicates the endpoint terminates traffic (and receive money 
	to its corresponding account). <br>
	(The default is that the user originates traffic). </td></tr>' ;
echo '<tr><td>NAS Address  &nbsp; </td> <td>Permit connection only to this NAS (IP address)</td></tr>' ;

echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2"> * Allowed Aliases is a REGULAR EXPRESSION. To allow an endpoint to register with any aliases, 
   write &quot;*&quot;. <br>To allow &quot;john&quot; and &quot;48581234&quot; aliases only, write &quot;^(john|48581234)$&quot;. &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">Assigned Aliases is a comma separated list. &nbsp;</td></tr>' ;
echo '<tr><td colspan="2">  &nbsp;</td></tr>' ;
echo '<tr><td colspan="2"> In a calling card type environment, there are two kinds of users: &nbsp;</td></tr>' ;

echo '<tr><td>Originators&nbsp; </td> <td>These correspond to the different different access numbers and
	hence originating tariffs.<br>
     You may need to find a way to ensure that different mobile networks origination charges are separated, and<br>
     to separate payphone calls from landlines.</td></tr>' ;
echo '<tr><td>Terminators&nbsp; </td> <td>Endpoints (probably gatekeepers) belonging to companies (accounts)
     providing termination services.</td></tr>' ;


echo '</table > ';

include "../local/tail.php";
?>

