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
            $read = array_merge($read, array_column($this->clients, 'socket'));
            $write = null;
            $except = null;

            $changedStreams = stream_select($read, $write, $except, null);

            if ($changedStreams === false) {
                throw new Exception("Error during stream_select.");
            }

            if (in_array($this->serverSocket, $read)) {
                $clientSocket = stream_socket_accept($this->serverSocket);
                if ($clientSocket) {
                    $this->handleClient($clientSocket);
                }
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
            fclose($client['socket']);
        }

        $this->clients = [];
        echo "Server stopped.\n";
    }

    private function handleClient($clientSocket)
    {
        if ($this->serverCertificate) {
            $context = stream_context_create([
                'ssl' => $this->serverCertificate,
            ]);
            stream_socket_enable_crypto($clientSocket, true, STREAM_CRYPTO_METHOD_TLS_SERVER);
        }

        // Read the request from the client
        $request = '';
        while (($line = fgets($clientSocket)) && rtrim($line) !== '') {
            $request .= $line;
        }

        // Debugging: Print raw request
        echo "Raw Request:\n$request\n";

        // Extract the request line (e.g., "GET /path?query=value HTTP/1.1")
        $requestLines = explode("\r\n", $request);
        $requestLine = $requestLines[0];

        // Extract URL and query string
        $url = '';
        $host = '';
        if (preg_match("/GET (.*?) HTTP/", $requestLine, $matches)) {
            $url = trim($matches[1]);
        }
        if (preg_match("/Host: (.*)\r\n/", $request, $matches)) {
            $host = trim($matches[1]);
        }

        // Remove leading '/' from URL if present
        $url = ltrim($url, '/');

        // Perform WebSocket handshake
        if ($this->performHandshake($clientSocket, $request)) {
            $this->clients[(int) $clientSocket] = [
                'socket' => $clientSocket,
                'host' => 'ws://'.$host . $url,
            ];
            echo "Client connected with URL: $url and Host: $host.\n";
        } else {
            fclose($clientSocket);
            echo "Client handshake failed.\n";
        }
    }



    private function performHandshake($clientSocket, $request)
    {
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
            $this->removeClient($clientSocket);
            echo "Client disconnected.\n";
            return;
        }

        // Check if client exists in the list
        if (!isset($this->clients[(int) $clientSocket])) {
            echo "Client not found.\n";
            $this->removeClient($clientSocket);
            return;
        }

        // Read data from the client
        $data = fread($clientSocket, 1024);

        // Check for read errors or empty data
        if ($data === false) {
            echo "Read error from client.\n";
            $this->removeClient($clientSocket);
            return;
        }

        if (empty($data)) {
            echo "No data received.\n";
            $this->removeClient($clientSocket);
            return; // Allow stream_select to handle disconnection
        }

        // Decode the WebSocket frame
        $decodedData = $this->decodeFrame($data);

        // Check if decoding was successful
        if ($decodedData === null) {
            echo "Failed to decode frame.\n";
            $this->removeClient($clientSocket);
            return; // Allow further processing of potentially valid frames
        }

        // Extract payload and check if it is valid UTF-8
        $payload = $decodedData['payload'];
        if (!mb_check_encoding($payload, 'UTF-8')) {
            echo "Invalid UTF-8 sequence.\n";
            $this->removeClient($clientSocket);
            return; // Allow further processing if necessary
        }

        // Log received message and broadcast it to other clients
        $clientData = $this->clients[(int) $clientSocket];
        $host = $clientData['host'];
        $this->broadcastMessage($payload);
    }

    private function decodeFrame($data)
    {
        if (strlen($data) < 2) {
            return null; // Not enough data to process
        }

        $byte1 = ord($data[0]);
        $byte2 = ord($data[1]);

        $opcode = $byte1 & 0x0F;
        if ($opcode !== 1) {
            // Not a text frame, ignore
            return null;
        }

        $length = $byte2 & 127;
        if ($length == 126) {
            if (strlen($data) < 8) {
                return null; // Not enough data to process
            }
            $length = unpack('n', substr($data, 2, 2))[1];
            $masks = substr($data, 4, 4);
            $payload = substr($data, 8);
        } elseif ($length == 127) {
            if (strlen($data) < 14) {
                return null; // Not enough data to process
            }
            $length = unpack('J', substr($data, 2, 8))[1];
            $masks = substr($data, 10, 4);
            $payload = substr($data, 14);
        } else {
            $masks = substr($data, 2, 4);
            $payload = substr($data, 6);
        }

        // Ensure the payload length matches the declared length
        if (strlen($payload) !== $length) {
            return null;
        }

        // Decode the payload
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
        // Check if the message is not empty
        if (trim($message) !== '') {
            foreach ($this->clients as $client) {
                fwrite($client['socket'], $this->encodeFrame($message));
            }
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

    private function removeClient($clientSocket)
    {
        fclose($clientSocket); // Close the socket properly
        unset($this->clients[(int) $clientSocket]); // Remove the client from the list
    }
}
