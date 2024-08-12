package messages.messageConverter;

import statemachines.server.ServerStateMachine;

public class ClientMessageConverter extends PQTLSMessageConverter{

    public ClientMessageConverter(ServerStateMachine statemachine) {
        super(statemachine);
    }

    @Override
    protected byte[] getIVAndIncrement() {
        return sharedSecret.getClientHandShakeIVAndIncrement();
    }

    @Override
    protected byte[] getHandshakeSecret() {
        return sharedSecret.getClientHandShakeSecret();
    }
}
