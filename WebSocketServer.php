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

        // Allow the script to run even after the client disconnects
        ignore_user_abort(true);

        // Run the server in the background
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
            // Prepare the array of sockets to pass to stream_select
            $read = [$this->serverSocket];
            $read = array_merge($read, $this->clients);
            $write = null;
            $except = null;

            // Check for socket activity
            $changedStreams = stream_select($read, $write, $except, null);

            if ($changedStreams === false) {
                throw new Exception("Error during stream_select.");
            }

            // Check if there's a new connection
            if (in_array($this->serverSocket, $read)) {
                $clientSocket = stream_socket_accept($this->serverSocket);
                $this->handleClient($clientSocket);
                $key = array_search($this->serverSocket, $read);
                unset($read[$key]); // Remove the server socket from the read array
            }

            // Handle data from existing clients
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
            $this->clients[] = $clientSocket;
            echo "Client connected.\n";
        } else {
            fclose($clientSocket);
            echo "Client handshake failed.\n";
        }
    }

    private function performHandshake($clientSocket)
    {
        $request = fread($clientSocket, 1024);
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
        if (feof($clientSocket)) {
            // Client disconnected
            fclose($clientSocket);
            $this->clients = array_filter($this->clients, function ($client) use ($clientSocket) {
                return $client !== $clientSocket;
            });
            echo "Client disconnected.\n";
            return;
        }

        $data = fread($clientSocket, 1024);
        if ($data === false || $data === '') {
            return;
        }

        $decodedData = $this->decodeFrame($data);
        if ($decodedData === null) {
            return;
        }

        $payload = $decodedData['payload'];
        if (!mb_check_encoding($payload, 'UTF-8')) {
            echo "Invalid UTF-8 sequence.\n";
            return;
        }

        echo "Received: {$payload}\n";

        // Example of broadcasting message to all clients
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
}

