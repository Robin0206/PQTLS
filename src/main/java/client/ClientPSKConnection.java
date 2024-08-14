package client;

import crypto.SharedSecretHolder;

import java.net.Socket;

public class ClientPSKConnection {
    private final SharedSecretHolder sharedSecretHolder;
    private final Socket socket;

    public ClientPSKConnection(SharedSecretHolder sharedSecretHolder, Socket socket) {
        this.sharedSecretHolder = sharedSecretHolder;
        this.socket = socket;
    }
}
