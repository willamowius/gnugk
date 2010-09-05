<?php
// functions to systematise the UI

///////////////////////////////////////////
// create a dropdown which allows selection by description, but returns the ID
// from table as $_POST['name'];
// returns the number of choices

function dropdown($label, $table, $name)
{
    global $connection;
    $query = "SELECT id, description from $table order by description";

    $result = pg_query($connection, $query)
        or die("<br>Cannot create dropdown from table \"$table\".");

    $rows = pg_num_rows($result);

    print("<td>$label</td><td><select name=\"$name\">");

    for ($row = 0; $row < $rows; $row++)
        {
        $id = pg_result($result, $row, 0);
        $desc = pg_result($result, $row, 1);

        print("<option value=\"$id\">$desc</option>");
        }
    print("</select></td>");
return($rows);
}
//////////////////////////////////////////

?>
