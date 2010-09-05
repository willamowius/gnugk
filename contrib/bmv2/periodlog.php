
<html>
<head></head>
<body>
<?php
include "local/connect.php";

$start = mktime(0,0,0, $_POST['smonth'], $_POST['sday'], $_POST['syear']);
$end = mktime(23,59,59, $_POST['emonth'], $_POST['eday'], $_POST['eyear']);

$sdate = date("D j M Y H:i:s", $start);
$edate =  date("D j M Y H:i:s", $end);


 print("<h2 align=\"center\">Call listing for calls for period <br />");
   print("from $sdate <br /> to $edate </h2>");

 $query = "SELECT disconnecttime, calledstationid, duration/60, cost, tariffdesc,
  currencysym, terminatecause 
 from voipcall where (connecttime::timestamp between '$sdate' and '$edate') 
   order by connecttime::timestamp ;";

 print("<table  align=\"center\">");
  print("<tr><td/>Time &nbsp; <td/> Called &nbsp; <td/>Destination <td/>Minutes &nbsp;
        <td/>Cost  <td/>Cause &nbsp;</tr> ");

  $result = pg_query($connection, $query) or die(" Unable to query the database ");

  $rows = pg_num_rows($result);


 for($li = 0; $li < $rows ; $li = $li+1) 
   {
   $d_time = pg_result($result, $li, 0);
   $ani = pg_result($result, $li, 1);
   $duration = number_format(pg_result($result, $li, 2), 2);
   $cost = number_format(pg_result($result, $li, 3), 2);

   $desc = pg_result($result, $li, 4);
   $currency = pg_result($result, $li, 5);
   $cause = pg_result($result, $li, 6);

     print("<tr><td/> $d_time &nbsp; <td/> &nbsp;$ani  <td/>&nbsp;$desc 
        <td/> $duration &nbsp; <td/> $currency &nbsp; $cost <td/>$cause &nbsp;</tr> ");
  }

 print("</table>");
 print("<p></p>");
 print("<p></p>");
 print("<p></p>");

pg_close($connection);

?>
</body>
</html>
