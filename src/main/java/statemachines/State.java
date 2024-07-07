package statemachines;

import messages.PQTLSMessage;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public abstract class State {
    public abstract void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException;
    public abstract PQTLSMessage getMessage();
    public abstract State next();
    public abstract void setPreviousMessage(PQTLSMessage message);
}
