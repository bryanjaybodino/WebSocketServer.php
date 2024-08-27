<?php
include_once "WebSocketServer.php";

echo "ws://127.0.0.1:8090"; // Default

// Add Room for selecting client to receive specific echo back message
echo "ws://127.0.0.1:8090?room=1";
echo "ws://127.0.0.1:8090?room=2";
echo "ws://127.0.0.1:8090?anyname=2";

// Usage
$server = new WebSocketServer(8090);
//$server->loadCertificate('/path/to/certificate.pem', 'password'); // Only if SSL/TLS is used
$server->start();

?>