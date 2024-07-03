package statemachines;

import messages.PQTLSMessage;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public abstract class State {
    public abstract void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException;
    public abstract PQTLSMessage getMessage();
    public abstract State next(PQTLSMessage message);
}
