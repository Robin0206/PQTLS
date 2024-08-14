package statemachines.client;

import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import messages.implementations.WrappedRecord;
import statemachines.PQTLSStateMachine;
import statemachines.State;
import statemachines.server.ServerStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class WaitingForEncryptedExtensionsState implements State {
    private WrappedRecord previousMessage;
    private ClientStateMachine stateMachine;


    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        stateMachine.serverEncryptedExtensions = previousMessage.getWrappedMessage();
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return new NullMessage();
    }

    @Override
    public State next() {
        return new CheckIfCertificatesTrustedState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        previousMessage = (WrappedRecord) message;
    }

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
        this.stateMachine = (ClientStateMachine) stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }
}
