<?php
try {
    throw new Exception('humpty dumpty');
} catch (Exception $e) {
    echo $e;
}
?>
