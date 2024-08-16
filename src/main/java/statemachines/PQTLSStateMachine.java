package statemachines;

import crypto.SharedSecretHolder;
import crypto.enums.CurveIdentifier;
import crypto.enums.PQTLSCipherSuite;
import messages.PQTLSMessage;
import java.util.ArrayList;

/**
 * @author Robin Kroker
 *Since there are fewer messages in this implementation than specified in https://www.rfc-editor.org/rfc/rfc8446,
 *I did not use the state machine architectures detailed at https://www.rfc-editor.org/rfc/rfc8446 appendix-A.1 and A-2
 *The state machines that I implemented use a more linear pattern and never jump back to a previous state, which makes them
 *much more simple and less error-prone
*/
public class PQTLSStateMachine {
    private CurveIdentifier[] supportedCurves;
    private SharedSecretHolder sharedSecretHolder;
    private byte[] supportedSignatureAlgorithms;
    private PQTLSCipherSuite chosenCipherSuite;
    private CurveIdentifier chosenCurve;
    private PQTLSCipherSuite[] supportedCipherSuites;
    private State currentState;
    private boolean stepWithoutWaiting;// signifies the client/server to immediately call step again without waiting for a new Message to arrive
    private boolean finished = false;
    private ArrayList<PQTLSMessage> messages;

    public PQTLSMessage step(PQTLSMessage previousMessage) throws Exception {
        getCurrentState().setStateMachine(this);
        getCurrentState().setPreviousMessage(previousMessage);
        if (isNotNullMessage(previousMessage)) {
            getMessages().add(previousMessage);
        }
        getCurrentState().calculate();
        PQTLSMessage result = getCurrentState().getMessage();
        if (result != null && isNotNullMessage(result)) {
            getMessages().add(result);
        }
        setStepWithoutWaiting(getCurrentState().stepWithoutWaitingForMessage());
        setCurrentState(getCurrentState().next());
        if(getCurrentState() instanceof FinishedState){
            this.setFinished(true);
        }
        return result;
    }

    protected boolean isNotNullMessage(PQTLSMessage message) {
        return message.getBytes()[0] != (byte) 0xff;
    }

    public CurveIdentifier[] getSupportedCurves() {
        return supportedCurves;
    }

    public SharedSecretHolder getSharedSecret() {
        return getSharedSecretHolder();
    }

    public ArrayList<PQTLSMessage> getMessages() {
        return messages;
    }

    public boolean stepWithoutWaiting() {
        return this.stepWithoutWaiting;
    }
    public void setStepWithoutWaiting(boolean stepWithoutWaiting){
        this.stepWithoutWaiting = stepWithoutWaiting;
    }

    public boolean finished() {
        return this.finished;
    }

    //getters and setters below here are automatically generated by intellij

    public PQTLSCipherSuite getChosenCipherSuite() {
        return this.chosenCipherSuite;
    }

    public void setSupportedCurves(CurveIdentifier[] supportedCurves) {
        this.supportedCurves = supportedCurves;
    }

    public SharedSecretHolder getSharedSecretHolder() {
        return sharedSecretHolder;
    }

    public void setSharedSecretHolder(SharedSecretHolder sharedSecretHolder) {
        this.sharedSecretHolder = sharedSecretHolder;
    }

    public byte[] getSupportedSignatureAlgorithms() {
        return supportedSignatureAlgorithms;
    }

    public void setSupportedSignatureAlgorithms(byte[] supportedSignatureAlgorithms) {
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
    }

    public void setChosenCipherSuite(PQTLSCipherSuite chosenCipherSuite) {
        this.chosenCipherSuite = chosenCipherSuite;
    }

    public CurveIdentifier getChosenCurve() {
        return chosenCurve;
    }

    public void setChosenCurve(CurveIdentifier chosenCurve) {
        this.chosenCurve = chosenCurve;
    }

    public PQTLSCipherSuite[] getSupportedCipherSuites() {
        return supportedCipherSuites;
    }

    public void setSupportedCipherSuites(PQTLSCipherSuite[] supportedCipherSuites) {
        this.supportedCipherSuites = supportedCipherSuites;
    }

    public State getCurrentState() {
        return currentState;
    }

    public void setCurrentState(State currentState) {
        this.currentState = currentState;
    }

    public void setFinished(boolean finished) {
        this.finished = finished;
    }

    public void setMessages(ArrayList<PQTLSMessage> messages) {
        this.messages = messages;
    }
}
