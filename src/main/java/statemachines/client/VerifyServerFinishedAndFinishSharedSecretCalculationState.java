package statemachines.client;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.FinishedMessage;
import messages.implementations.WrappedRecord;
import messages.implementations.alerts.AlertDescription;
import messages.implementations.alerts.AlertLevel;
import messages.implementations.alerts.PQTLSAlertMessage;
import misc.ByteUtils;
import misc.Constants;
import statemachines.FinishedState;
import statemachines.PQTLSStateMachine;
import statemachines.State;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author Robin Kroker
This state is responsible for verifying the servers finished message.
It is also responsible for calling the deriveSecretsAfterFinish Method of the SharedSecretHolder.
It expects a Wrapped Record with the servers finished message in it as the argument to setPreviousMessage().
If the message cant be decrypted or the servers finished message cant be verified, getMessage will return a decrypt error alert.
Otherwise, getMessage will return a wrapped Record with the clients FinishedMessage in it.
Next returns the FinishedState.
 */

public class VerifyServerFinishedAndFinishSharedSecretCalculationState implements State {
    private ArrayList<byte[]> concatenatedMessages;
    private ClientStateMachine stateMachine;
    private FinishedMessage serverFinishedMessage;
    private PQTLSAlertMessage alertMessage;

    @Override
    public void calculate() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        //verify serverFinishedMessage
        setConcatenatedMessagesUntilServerEncryptedExtensions();
        verifyServerFinishedMessage();
        //recalculate for own verify data
        resetCalculatedMessages();
        finishSharedSecretCalculation();
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 89
        if(!stateMachine.verifiedServerFinishedMessage){
            this.alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.decrypt_error);
        }
        if(this.alertMessage == null){
            stateMachine.setFinished(true);
        }
    }

    private void finishSharedSecretCalculation() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        ArrayList<byte[]> buffer = new ArrayList<>();
        for (int i = 0; i < stateMachine.getMessages().size(); i++) {
            buffer.add(stateMachine.getMessages().get(i).getBytes());
        }
        stateMachine.getSharedSecretHolder().deriveSecretsAfterFinish(ByteUtils.flatten(buffer));
    }

    private void resetCalculatedMessages() {
        concatenatedMessages.clear();
        for(PQTLSMessage message : stateMachine.getMessages()){
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
                stateMachine.getSharedSecretHolder().getServerHandShakeSecret(),
                stateMachine.getSharedSecretHolder().getHashName()
        ).getVerifyData();
    }

    private void setConcatenatedMessagesUntilServerEncryptedExtensions() {
        concatenatedMessages = new ArrayList<>();
        for(int i = 0; i < 3; i++){
            concatenatedMessages.add(stateMachine.getMessages().get(i).getBytes());
        }
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        if(!(alertMessage == null)){
            return new WrappedRecord(
                    alertMessage,
                    Constants.ALERT_MESSAGE,
                    CryptographyModule.keys.byteArrToSymmetricKey(
                            stateMachine.getSharedSecretHolder().getClientHandShakeSecret(),
                            stateMachine.symmetricAlgorithm
                    ),
                    stateMachine.getSharedSecretHolder().getClientHandShakeIVAndIncrement(),
                    stateMachine.getChosenCipherSuite()
            );
        }
        return new WrappedRecord(
                new FinishedMessage(
                        concatenatedMessages,
                        stateMachine.getSharedSecretHolder().getClientHandShakeSecret(),
                        stateMachine.getSharedSecretHolder().getHashName()
                ),
                Constants.HANDSHAKE_TYPE_FINISHED,
                CryptographyModule.keys.byteArrToSymmetricKey(
                        stateMachine.getSharedSecretHolder().getClientHandShakeSecret(),
                        stateMachine.symmetricAlgorithm
                ),
                stateMachine.getSharedSecretHolder().getClientHandShakeIVAndIncrement(),
                stateMachine.getChosenCipherSuite()
        );
    }

    @Override
    public State next() {
        return new FinishedState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.serverFinishedMessage = (FinishedMessage) (((WrappedRecord)message).getWrappedMessage());
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
