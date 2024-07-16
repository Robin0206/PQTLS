package statemachines.server;

import messages.PQTLSMessage;
import messages.implementations.FinishedMessage;
import messages.implementations.WrappedRecord;
import misc.ByteUtils;
import statemachines.State;
import statemachines.client.ClientStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

public class VerifyClientFinishedState implements State {
    private ServerStateMachine stateMachine;
    private FinishedMessage clientFinishedMessage;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        verifyClientVerifyData();
    }

    private void verifyClientVerifyData() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] clientVerifyData = clientFinishedMessage.getVerifyData();
        byte[] recalculatedClientVerifyData = recalculateClientVerifyData();
        stateMachine.verifiedClientFinished = Arrays.equals(clientVerifyData, recalculatedClientVerifyData);
    }

    private byte[] recalculateClientVerifyData() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        ArrayList<byte[]> concatenatedMessages = new ArrayList<>();
        for (int i = 0; i < stateMachine.messages.size()-1; i++) {
            concatenatedMessages.add(stateMachine.messages.get(i).getBytes());
        }
        return new FinishedMessage(
                concatenatedMessages,
                stateMachine.sharedSecret.getClientHandShakeSecret(),
                stateMachine.sharedSecret.getHashName()
        ).getVerifyData();
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return null;
    }

    @Override
    public State next() {
        return null;
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.clientFinishedMessage = (FinishedMessage)(((WrappedRecord)message).getWrappedMessage());
    }

    @Override
    public void setStateMachine(ClientStateMachine stateMachine) {

    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }
}
