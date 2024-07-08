package statemachines;

import messages.PQTLSMessage;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public abstract class State {
    public abstract void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException;
    public abstract PQTLSMessage getMessage();
    public abstract State next();
    public abstract void setPreviousMessage(PQTLSMessage message);
    public abstract void setStateMachine(ClientStateMachine stateMachine);
    public abstract void setStateMachine(ServerStateMachine stateMachine);
}
