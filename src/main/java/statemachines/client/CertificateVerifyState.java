package statemachines.client;

import messages.PQTLSMessage;
import messages.implementations.CertificateVerifyMessage;
import messages.implementations.NullMessage;
import messages.implementations.WrappedRecord;
import misc.ByteUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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

public class CertificateVerifyState implements State {
    private CertificateVerifyMessage certificateVerifyMessage;
    private byte[] signatureSendByServer;
    private ClientStateMachine stateMachine;
    private byte[] concatenatedMessages;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        setSignatureSendByServer();
        setConcatenatedMessages();
        verifySignature();
    }

    private void setConcatenatedMessages() {
        ArrayList<Byte> buffer = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            for (Byte b : stateMachine.messages.get(i).getBytes()) {
                buffer.add(b);
            }
        }
        concatenatedMessages = ByteUtils.toByteArray(buffer);
    }

    private void verifySignature() throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, CertificateException, InvalidKeyException {
        Signature signature = Signature.getInstance(stateMachine.sigAlgUsedByServer, "BCPQC");
        signature.initVerify(new JcaX509CertificateConverter().getCertificate(stateMachine.certificateUsedByServer).getPublicKey());
        signature.update(this.concatenatedMessages);
        stateMachine.signatureValid = signature.verify(signatureSendByServer);
    }

    private void setSignatureSendByServer() {
        signatureSendByServer = certificateVerifyMessage.getSignature();
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return new NullMessage();
    }

    @Override
    public State next() {
        return new VerifyServerFinishedState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.certificateVerifyMessage = (CertificateVerifyMessage) (((WrappedRecord)message).getWrappedMessage());
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
