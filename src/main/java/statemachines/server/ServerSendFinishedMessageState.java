package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.FinishedMessage;
import messages.implementations.WrappedRecord;
import misc.Constants;
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

public class ServerSendFinishedMessageState implements State {
    private ArrayList<byte[]> concatenatedMessages;
    private ServerStateMachine stateMachine;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        setConcatenatedMessages();
    }

    private void setConcatenatedMessages() {
        concatenatedMessages = new ArrayList<>();
        for(int i = 0; i < 3; i++){
            concatenatedMessages.add(stateMachine.getMessages().get(i).getBytes());
        }
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return new WrappedRecord(
                new FinishedMessage(
                        concatenatedMessages,
                        stateMachine.getSharedSecretHolder().getServerHandShakeSecret(),
                        stateMachine.getSharedSecretHolder().getHashName()
                ),
                Constants.HANDSHAKE_TYPE_FINISHED,
                CryptographyModule.keys.byteArrToSymmetricKey(
                        stateMachine.getSharedSecretHolder().getServerHandShakeSecret(),
                        stateMachine.getPreferredSymmetricAlgorithm()
                ),
                stateMachine.getSharedSecretHolder().getServerHandShakeIVAndIncrement(),
                stateMachine.getChosenCipherSuite()
        );
    }

    @Override
    public State next() {
        return new VerifyClientFinishedAndFinishSharedSecretCalculationState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {

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
