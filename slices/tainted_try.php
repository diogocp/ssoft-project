<?php
try {
    $q = "SELECT * FROM users WHERE sex='"
        . mysql_real_escape_string($_GET['sex'])
        . "';";
    $result = mysql_query($q);
    $average_age = 0;
    while ($usr = mysql_fetch_assoc($result)) {
        $average_age += $usr['age'];
        $count += 1;
    }
    echo $average_age / $count;
} catch (DivisionByZeroError $e) {
    echo "Error querying by " . $_GET['sex'] . " sex.";
}
