package statemachines.client;

import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import messages.implementations.WrappedRecord;
import statemachines.PQTLSStateMachine;
import statemachines.State;

/**
 * @author Robin Kroker
 */
public class WaitingForEncryptedExtensionsState implements State {
    private WrappedRecord previousMessage;
    private ClientStateMachine stateMachine;


    @Override
    public void calculate() {
        stateMachine.serverEncryptedExtensions = previousMessage.getWrappedMessage();
    }

    @Override
    public PQTLSMessage getMessage() {
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
