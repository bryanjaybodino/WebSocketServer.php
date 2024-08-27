<?php

class WebSocketServer
{
    private $serverSocket;
    private $clients = [];
    private $rooms = [];
    private $isRunning = false;
    private $serverCertificate;

    public function __construct($port)
    {
        $this->serverSocket = stream_socket_server("tcp://0.0.0.0:$port", $errno, $errstr);
        if (!$this->serverSocket) {
            throw new Exception("Could not create server: $errstr ($errno)");
        }

        ignore_user_abort(true);

        if (php_sapi_name() !== 'cli') {
            header('Connection: close');
            header('Content-Length: 0');
            ob_end_flush();
            flush();
            if (function_exists('fastcgi_finish_request')) {
                fastcgi_finish_request();
            }
        }
    }

    public function loadCertificate($path, $password)
    {
        $this->serverCertificate = [
            'local_cert' => $path,
            'passphrase' => $password,
        ];
    }

    public function start()
    {
        $this->isRunning = true;
        echo "Server started. Waiting for clients...\n";

        while ($this->isRunning) {
            $read = [$this->serverSocket];
            $read = array_merge($read, $this->clients);
            $write = null;
            $except = null;

            $changedStreams = stream_select($read, $write, $except, null);

            if ($changedStreams === false) {
                throw new Exception("Error during stream_select.");
            }

            if (in_array($this->serverSocket, $read)) {
                $clientSocket = stream_socket_accept($this->serverSocket);
                $this->handleClient($clientSocket);
                $key = array_search($this->serverSocket, $read);
                unset($read[$key]);
            }

            foreach ($read as $clientSocket) {
                $this->processClient($clientSocket);
            }
        }
    }

    public function stop()
    {
        $this->isRunning = false;
        fclose($this->serverSocket);

        foreach ($this->clients as $client) {
            fclose($client);
        }

        $this->clients = [];
        echo "Server stopped.\n";
    }

    private function handleClient($clientSocket)
    {
        if ($this->serverCertificate) {
            stream_context_set_option($clientSocket, 'ssl', 'local_cert', $this->serverCertificate['local_cert']);
            stream_context_set_option($clientSocket, 'ssl', 'passphrase', $this->serverCertificate['passphrase']);
            stream_socket_enable_crypto($clientSocket, true, STREAM_CRYPTO_METHOD_TLS_SERVER);
        }

        $handshake = $this->performHandshake($clientSocket);
        if ($handshake) {
            $this->clients[(int) $clientSocket] = $clientSocket; // Use socket resource ID as key
            echo "Client connected.\n";
        } else {
            fclose($clientSocket);
            echo "Client handshake failed.\n";
        }
    }



    private function performHandshake($clientSocket)
    {
        // Read the request from the client
        $request = '';
        while (($line = fgets($clientSocket)) && rtrim($line) !== '') {
            $request .= $line;
        }

        // Split the request into lines
        $lines = explode("\r\n", $request);

        // Extract the request line (e.g., GET /path HTTP/1.1)
        $requestLine = array_shift($lines);
        $url = '';
        if (preg_match('/GET\s+(.*?)\s+HTTP/', $requestLine, $matches)) {
            $url = $matches[1];
        }

        // Extract the Host header
        $host = '';
        foreach ($lines as $line) {
            if (preg_match('/^Host:\s*(.*)$/i', $line, $matches)) {
                $host = trim($matches[1]);
                break;
            }
        }

        // Store the URL and Host in the clients array
        $this->clients[(int) $clientSocket] = [
            'socket' => $clientSocket,
            'url' => $url,
            'host' => $host
        ];

        // Handle the WebSocket key and perform the handshake
        if (preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $request, $matches)) {
            $key = trim($matches[1]);
            $acceptKey = base64_encode(pack('H*', sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
            $response = "HTTP/1.1 101 Switching Protocols\r\n";
            $response .= "Upgrade: websocket\r\n";
            $response .= "Connection: Upgrade\r\n";
            $response .= "Sec-WebSocket-Accept: $acceptKey\r\n";
            $response .= "\r\n";
            fwrite($clientSocket, $response);
            return true;
        }

        return false;
    }


    private function processClient($clientSocket)
    {
        // Check if client is disconnected
        if (feof($clientSocket)) {
            fclose($clientSocket);
            unset($this->clients[(int) $clientSocket]); // Remove the client from the list
            echo "Client disconnected.\n";
            return;
        }

        // Check if client exists in the list
        if (!isset($this->clients[(int) $clientSocket])) {
            echo "Client not found.\n";
            return;
        }

        // Access client data
        $clientData = $this->clients[(int) $clientSocket];
        $url = $clientData['url'];
        $host = $clientData['host'];

        // Read data from the client
        $data = fread($clientSocket, 1024);
        if ($data === false || $data === '') {
            return;
        }

        // Decode the WebSocket frame
        $decodedData = $this->decodeFrame($data);
        if ($decodedData === null) {
            return;
        }

        // Check if payload is valid UTF-8
        $payload = $decodedData['payload'];
        if (!mb_check_encoding($payload, 'UTF-8')) {
            echo "Invalid UTF-8 sequence.\n";
            fclose($clientSocket); // Close the socket properly
            unset($this->clients[(int) $clientSocket]); // Remove the client from the list
            return;
        }

        // Log received message and broadcast it to other clients
        echo "Received from URL {$url} (Host: {$host}): {$payload}\n";
        $this->broadcastMessage($payload);
    }


    private function decodeFrame($data)
    {
        $length = ord($data[1]) & 127;

        if ($length == 126) {
            $masks = substr($data, 4, 4);
            $payload = substr($data, 8);
        } elseif ($length == 127) {
            $masks = substr($data, 10, 4);
            $payload = substr($data, 14);
        } else {
            $masks = substr($data, 2, 4);
            $payload = substr($data, 6);
        }

        $decoded = '';
        for ($i = 0; $i < strlen($payload); ++$i) {
            $decoded .= $payload[$i] ^ $masks[$i % 4];
        }

        return [
            'payload' => $decoded,
        ];
    }

    private function broadcastMessage($message)
    {
        foreach ($this->clients as $client) {
            fwrite($client, $this->encodeFrame($message));
        }
    }

    private function encodeFrame($payload)
    {
        $frameHead = [];
        $payloadLength = strlen($payload);

        $frameHead[0] = 129;

        if ($payloadLength <= 125) {
            $frameHead[1] = $payloadLength;
        } elseif ($payloadLength >= 126 && $payloadLength <= 65535) {
            $frameHead[1] = 126;
            $frameHead[2] = ($payloadLength >> 8) & 255;
            $frameHead[3] = $payloadLength & 255;
        } else {
            $frameHead[1] = 127;
            for ($i = 7; $i >= 0; --$i) {
                $frameHead[2 + $i] = ($payloadLength >> ($i * 8)) & 255;
            }
        }

        foreach ($frameHead as $i => $frame) {
            $frameHead[$i] = chr($frame);
        }

        return implode('', $frameHead) . $payload;
    }


    private function joinRoom($client, $roomId)
    {
        $clientId = (int) $client;
        if (!isset($this->rooms[$roomId])) {
            $this->rooms[$roomId] = [];
        }

        $this->rooms[$roomId][] = $this->clients[$clientId]['socket'];
        $this->clients[$clientId]['room'] = $roomId;
        echo "Client joined room $roomId.\n";
    }

}

