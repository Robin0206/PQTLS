package statemachines;

import messages.PQTLSMessage;
import messages.implementations.NullMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class FinishedState implements State {

    @Override
    public void calculate() throws Exception {

    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return new NullMessage();
    }

    @Override
    public State next() {
        return null;
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {

    }

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }
}
