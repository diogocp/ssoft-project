<?php
$arg3=$_POST['nis'];
$arg2=$arg3;
$arg1=$arg2;
while ($indarg == "") {
      $query="SELECT *FROM siswa WHERE nis='$arg3'";
      $arg3 = $arg2;
      $arg2 = $arg1;
      $arg1 = "safe";
      $indarg = substr($indarg,1);
}
$q=mysql_query($query,$koneksi);
?>
