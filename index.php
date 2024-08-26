<?php
include_once "WebSocketServer.php";


echo "ws://127.0.0.1:8090<br>";
echo "ws://localhost:8090<br>";
echo "ws://{Your IPv4}:8090";

// Usage
$server = new WebSocketServer(8090);
//$server->loadCertificate('/path/to/certificate.pem', 'password'); // Only if SSL/TLS is used
$server->start();

?>