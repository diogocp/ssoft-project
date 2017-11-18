<?php
$_POST['nis']='nis';
$nis=$_POST['nis'];
$query="SELECT *FROM siswa WHERE nis='$nis'";
$q=mysql_query($query,$koneksi);
?>
