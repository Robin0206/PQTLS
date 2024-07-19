package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.FinishedMessage;
import messages.implementations.WrappedRecord;
import messages.implementations.alerts.AlertDescription;
import messages.implementations.alerts.AlertLevel;
import messages.implementations.alerts.PQTLSAlertMessage;
import misc.ByteUtils;
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
import java.util.Arrays;

public class VerifyClientFinishedState implements State {
    private ServerStateMachine stateMachine;
    private FinishedMessage clientFinishedMessage;
    private PQTLSAlertMessage alertMessage;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        verifyClientVerifyData();
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 89
        if(!stateMachine.verifiedClientFinished){
            this.alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.decrypt_error);
        }
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
        if(!(alertMessage == null)){
            return new WrappedRecord(
                    alertMessage,
                    Constants.ALERT_MESSAGE,
                    CryptographyModule.keys.byteArrToSymmetricKey(
                            stateMachine.sharedSecret.getServerHandShakeSecret(),
                            stateMachine.getPreferredSymmetricAlgorithm()
                    ),
                    stateMachine.sharedSecret.getServerHandShakeIVAndIncrement(),
                    stateMachine.preferredCipherSuite
            );
        }

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
