package statemachines.client;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.CertificateVerifyMessage;
import messages.implementations.NullMessage;
import messages.implementations.WrappedRecord;
import messages.implementations.alerts.AlertDescription;
import messages.implementations.alerts.AlertLevel;
import messages.implementations.alerts.PQTLSAlertMessage;
import misc.ByteUtils;
import misc.Constants;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import statemachines.PQTLSStateMachine;
import statemachines.State;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/**
 * @author Robin Kroker
Class responsible for verifying the signature the server sent in his CertificateVerify Message.
Expects a Wrapped Record with an CertificateVerify Message in it as an argument to setPreviousMessage.
getMessage Returns a bad certificate alert if it cant verify the signature otherwise a NullMessage.
next returns a VerifyServerFinishedAndFinishSharedSecretCalculationState Object
 */

public class SignatureVerifyState implements State {
    private CertificateVerifyMessage certificateVerifyMessage;
    private byte[] signatureSendByServer;
    private ClientStateMachine stateMachine;
    private byte[] concatenatedMessages;
    private PQTLSAlertMessage alertMessage;

    @Override
    public void calculate() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        setSignatureSendByServer();
        setConcatenatedMessages();
        verifySignature();
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 88
        if (!stateMachine.signatureValid) {
            alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.bad_certificate);
        }
    }

    private void setConcatenatedMessages() {
        ArrayList<Byte> buffer = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            for (Byte b : stateMachine.getMessages().get(i).getBytes()) {
                buffer.add(b);
            }
        }
        concatenatedMessages = ByteUtils.toByteArray(buffer);
    }

    private void verifySignature() throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, CertificateException, InvalidKeyException, InvalidKeySpecException {
        stateMachine.signatureValid = CryptographyModule.certificate.verifySignature(
                CryptographyModule.keys.byteArrToPublicKey(
                        new JcaX509CertificateConverter().getCertificate(stateMachine.certificateUsedByServer).getPublicKey().getEncoded(),
                        stateMachine.sigAlgUsedByServer,
                        "BCPQC"
                ),
                stateMachine.sigAlgUsedByServer,
                this.concatenatedMessages,
                signatureSendByServer
        );
    }

    private void setSignatureSendByServer() {
        signatureSendByServer = certificateVerifyMessage.getSignature();
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        if (!(alertMessage == null)) {
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
        return new NullMessage();
    }

    @Override
    public State next() {
        return new VerifyServerFinishedAndFinishSharedSecretCalculationState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.certificateVerifyMessage = (CertificateVerifyMessage) (((WrappedRecord) message).getWrappedMessage());
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
