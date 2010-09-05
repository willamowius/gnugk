
<html>
<head></head>
<body>
<?php
include "local/connect.php";

$start = mktime(0,0,0, $_POST['smonth'], $_POST['sday'], $_POST['syear']);
$end = mktime(23,59,59, $_POST['emonth'], $_POST['eday'], $_POST['eyear']);

$sdate = date("D j M Y H:i:s", $start);
$edate =  date("D j M Y H:i:s", $end);
$carrier =  $_POST['carrier'] . "%";


if($carrier == "%")
 {
 print("<h2 align=\"center\">Call listing for calls for period, by prefix <br />");
   print("from $sdate <br /> to $edate </h2>");

 $query = "SELECT disconnecttime, callingstationid, duration, cost, calledstationid, prefix 
        from voipcall 
        where (disconnecttime::timestamp between '$sdate' and '$edate') 
        order by prefix, disconnecttime::timestamp ;";

 print("<table  align=\"center\">");
  print("<tr><td>Time &nbsp; <td> Caller &nbsp; <td>Seconds &nbsp;<td>Cost (Euros) <td>Called &nbsp;</tr> ");

  $result = pg_query($connection, $query) or die(" Unable to query the database ");

  $rows = pg_num_rows($result);


 for($li = 0; $li < $rows ; $li = $li+1) 
   {
   $d_time = pg_result($result, $li, 0);
   $ani = pg_result($result, $li, 1);
   $duration = number_format(pg_result($result, $li, 2), 2);
   $cost = number_format(pg_result($result, $li, 3), 2);

      $dni = pg_result($result, $li, 4);

     print("<tr><td> $d_time &nbsp; <td> &nbsp;$ani  <td>&nbsp;$duration <td> &nbsp; 
      $cost <td>$dni &nbsp;</tr> ");
  }
 }
else
 {
  print("<h2 align=\"center\">Call listing for calls to \"$carrier\" for period <br />");
     print("from $sdate <br /> to $edate </h2>");

  $query = "SELECT disconnecttime, 'ani', duration, cost/100, calledstationid, prefix 
        from voipcall 
        where (disconnecttime::timestamp between '$sdate' and '$edate') 
        and calledstationid like '$carrier' order by prefix, disconnecttime::timestamp ;";


 print("<table  align=\"center\">");
   print("<tr><td>Time &nbsp; <td> Number &nbsp; <td>Seconds &nbsp;
   <td>Cost (Euros)<td>Carrier &nbsp; </tr> ");

  $result = pg_query($connection, $query) or die(" Unable to query the database ");
 $rows = pg_num_rows($result);

 for($li = 0; $li < $rows ; $li = $li+1) 
   {
   $d_time = pg_result($result, $li, 0);
   $ani = pg_result($result, $li, 1);
   $duration = number_format(pg_result($result, $li, 2), 2);
   $cost = number_format(pg_result($result, $li, 3), 2);
    $carrier = pg_result($result, $li, 4);

   print("<tr><td> $d_time &nbsp; <td> &nbsp;$ani  <td>&nbsp;$duration <td> &nbsp; 
   $cost <td>$carrier &nbsp;</tr> ");
   }
 }

 print("</table>");
 print("<p></p>");
 print("<p></p>");
 print("<p></p>");

pg_close($connection);

?>
</body>
</html>
