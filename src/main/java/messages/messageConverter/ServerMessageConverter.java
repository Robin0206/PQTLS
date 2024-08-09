package messages.messageConverter;

import statemachines.client.ClientStateMachine;

public class ServerMessageConverter extends PQTLSMessageConverter{

    public ServerMessageConverter(ClientStateMachine statemachine) {
        super(statemachine);
    }

    @Override
    protected byte[] getIVAndIncrement() {
        return sharedSecret.getServerHandShakeIVAndIncrement();
    }

    @Override
    protected byte[] getHandshakeSecret() {
        return sharedSecret.getServerHandShakeSecret();
    }
}
