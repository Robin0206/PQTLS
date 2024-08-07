package client;

import statemachines.client.ClientStateMachine;

import java.net.Socket;

public class ClientHandShakeConnection {
    private final ClientStateMachine statemachine;
    private final Socket socket;

    public ClientHandShakeConnection(ClientStateMachine stateMachine, Socket socket) {
        this.statemachine = stateMachine;
        this.socket = socket;
    }

    public ClientStateMachine getStateMachine() {
        return statemachine;
    }
}
