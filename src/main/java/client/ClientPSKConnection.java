package client;

import crypto.SharedSecret;

import java.net.Socket;

public class ClientPSKConnection {
    private final SharedSecret sharedSecret;
    private final Socket socket;

    public ClientPSKConnection(SharedSecret sharedSecret, Socket socket) {
        this.sharedSecret = sharedSecret;
        this.socket = socket;
    }
}
