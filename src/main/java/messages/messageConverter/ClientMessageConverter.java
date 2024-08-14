package messages.messageConverter;

import statemachines.server.ServerStateMachine;

public class ClientMessageConverter extends PQTLSMessageConverter{

    public ClientMessageConverter(ServerStateMachine statemachine) {
        super(statemachine);
    }

    @Override
    protected byte[] getIVAndIncrement() {
        return sharedSecretHolder.getClientHandShakeIVAndIncrement();
    }

    @Override
    protected byte[] getHandshakeSecret() {
        return sharedSecretHolder.getClientHandShakeSecret();
    }
}
