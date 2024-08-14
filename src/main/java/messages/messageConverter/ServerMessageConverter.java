package messages.messageConverter;

import statemachines.client.ClientStateMachine;

public class ServerMessageConverter extends PQTLSMessageConverter{

    public ServerMessageConverter(ClientStateMachine statemachine) {
        super(statemachine);
    }

    @Override
    protected byte[] getIVAndIncrement() {
        return sharedSecretHolder.getServerHandShakeIVAndIncrement();
    }

    @Override
    protected byte[] getHandshakeSecret() {
        return sharedSecretHolder.getServerHandShakeSecret();
    }
}
