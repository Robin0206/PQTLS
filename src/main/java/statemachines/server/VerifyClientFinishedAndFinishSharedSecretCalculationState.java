package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.FinishedMessage;
import messages.implementations.NullMessage;
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
This state is responsible for building the Certificate Verify Message.
It is also responsible for calling the deriveSecretsAfterFinish Method of the SharedSecretHolder.
The setPreviousMessage method expects a WrappedRecord with the clients
FinishedMessage in it.
The method getMessage can return:
    -a NullMessage
    -a decrypt error alert(if the clients FinishedMessage cant be verified)
The method next returns the FinishedState.
 */
public class VerifyClientFinishedAndFinishSharedSecretCalculationState implements State {
    private ServerStateMachine stateMachine;
    private FinishedMessage clientFinishedMessage;
    private PQTLSAlertMessage alertMessage;

    @Override
    public void calculate() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        verifyClientVerifyData();
        finishSharedSecretCalculation();
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 89
        if(!stateMachine.verifiedClientFinished){
            this.alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.decrypt_error);
        }else{
            stateMachine.setFinished(true);
        }
    }

    private void finishSharedSecretCalculation() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        ArrayList<byte[]> buffer =  new ArrayList<>();
        for (int i = 0; i < stateMachine.getMessages().size() - 1; i++) {//loop over all messages except the last(which is the client finished message)
            buffer.add(stateMachine.getMessages().get(i).getBytes());
        }
        stateMachine.getSharedSecretHolder().deriveSecretsAfterFinish(ByteUtils.flatten(buffer));
    }

    private void verifyClientVerifyData() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] clientVerifyData = clientFinishedMessage.getVerifyData();
        byte[] recalculatedClientVerifyData = recalculateClientVerifyData();
        stateMachine.verifiedClientFinished = Arrays.equals(clientVerifyData, recalculatedClientVerifyData);
    }

    private byte[] recalculateClientVerifyData() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        ArrayList<byte[]> concatenatedMessages = new ArrayList<>();
        for (int i = 0; i < stateMachine.getMessages().size()-1; i++) {
            concatenatedMessages.add(stateMachine.getMessages().get(i).getBytes());
        }
        return new FinishedMessage(
                concatenatedMessages,
                stateMachine.getSharedSecretHolder().getClientHandShakeSecret(),
                stateMachine.getSharedSecretHolder().getHashName()
        ).getVerifyData();
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        if(!(alertMessage == null)){
            return new WrappedRecord(
                    alertMessage,
                    Constants.ALERT_MESSAGE,
                    CryptographyModule.keys.byteArrToSymmetricKey(
                            stateMachine.getSharedSecretHolder().getServerHandShakeSecret(),
                            stateMachine.getPreferredSymmetricAlgorithm()
                    ),
                    stateMachine.getSharedSecretHolder().getServerHandShakeIVAndIncrement(),
                    stateMachine.getChosenCipherSuite()
            );
        }

        return new NullMessage();
    }

    @Override
    public State next() {
        return new FinishedState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.clientFinishedMessage = (FinishedMessage)(((WrappedRecord)message).getWrappedMessage());
    }

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
        this.stateMachine = (ServerStateMachine) stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }
}
