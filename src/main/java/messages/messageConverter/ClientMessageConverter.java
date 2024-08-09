package messages.messageConverter;

import statemachines.client.ClientStateMachine;

public class ClientMessageConverter extends PQTLSMessageConverter{

    public ClientMessageConverter(ClientStateMachine statemachine) {
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
