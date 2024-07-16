package statemachines.client;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.FinishedMessage;
import messages.implementations.WrappedRecord;
import misc.Constants;
import statemachines.State;
import statemachines.server.ServerStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

public class VerifyServerFinishedState implements State {
    private ArrayList<byte[]> concatenatedMessages;
    private ClientStateMachine stateMachine;
    private FinishedMessage serverFinishedMessage;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        //verify serverFinishedMessage
        setConcatenatedMessagesUntilServerEncryptedExtensions();
        verifyServerFinishedMessage();
        //recalculate for own verify data
        resetCalculatedMessages();
    }

    private void resetCalculatedMessages() {
        concatenatedMessages.clear();
        for(PQTLSMessage message : stateMachine.messages){
            concatenatedMessages.add(message.getBytes());
        }
    }

    private void verifyServerFinishedMessage() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] serverVerifyData = serverFinishedMessage.getVerifyData();
        byte[] recalculatedServerVerifyData = calculateServerVerifyData();
        stateMachine.verifiedServerFinishedMessage = Arrays.equals(serverVerifyData, recalculatedServerVerifyData);
    }

    private byte[] calculateServerVerifyData() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        return new FinishedMessage(
                concatenatedMessages,
                stateMachine.sharedSecret.getServerHandShakeSecret(),
                stateMachine.sharedSecret.getHashName()
        ).getVerifyData();
    }

    private void setConcatenatedMessagesUntilServerEncryptedExtensions() {
        concatenatedMessages = new ArrayList<>();
        for(int i = 0; i < 3; i++){
            concatenatedMessages.add(stateMachine.messages.get(i).getBytes());
        }
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return new WrappedRecord(
                new FinishedMessage(
                        concatenatedMessages,
                        stateMachine.sharedSecret.getClientHandShakeSecret(),
                        stateMachine.sharedSecret.getHashName()
                ),
                Constants.HANDSHAKE_TYPE_FINISHED,
                CryptographyModule.keys.byteArrToSymmetricKey(
                        stateMachine.sharedSecret.getClientHandShakeSecret(),
                        stateMachine.symmetricAlgorithm
                ),
                stateMachine.sharedSecret.getClientHandShakeIVAndIncrement(),
                stateMachine.chosenCipherSuite
        );
    }

    @Override
    public State next() {
        return null;
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.serverFinishedMessage = (FinishedMessage) (((WrappedRecord)message).getWrappedMessage());
    }

    @Override
    public void setStateMachine(ClientStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {

    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }
}
