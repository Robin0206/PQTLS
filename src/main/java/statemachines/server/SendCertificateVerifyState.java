package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.CertificateVerifyMessage;
import messages.implementations.WrappedRecord;
import misc.ByteUtils;
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
This State doesn't make use of any prior message.
(The Statemachine calls the setPreviousMessage method with an NullMessage
as an argument)
The method getMessage doesn't return any alert messages, it only returns
the CertificateVerifyMessage.
The method next returns the ServerSendFinishedMessageState.
 */

public class SendCertificateVerifyState implements State {

    private ServerStateMachine stateMachine;
    byte[] signature;
    byte[] messagesToSign;
    private PrivateKey privateKey;

    @Override
    public void calculate() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        determinePrivateKeyToUse();
        setMessagesToSign();
        setSignature();
    }

    private void setMessagesToSign() {
        ArrayList<Byte> messagesConcatenated = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            for(Byte b : stateMachine.getMessages().get(i).getBytes()){
                messagesConcatenated.add(b);
            }
        }
        messagesToSign = ByteUtils.toByteArray(messagesConcatenated);
    }

    private void setSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureAlg = Signature.getInstance(stateMachine.sigAlgUsedInCertificate);
        signatureAlg.initSign(privateKey);
        signatureAlg.update(messagesToSign);
        signature = signatureAlg.sign();
    }

    private void determinePrivateKeyToUse() {
        for(KeyPair keyPair : stateMachine.signatureKeyPairs){
            if(Arrays.equals(
                    keyPair.getPublic().getEncoded(),
                    stateMachine.publicKeyUsedInCertificate.getEncoded()
            )){

                this.privateKey = keyPair.getPrivate();
                return;
            }
        }
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return new WrappedRecord(
                new CertificateVerifyMessage(signature, true),
                (byte) 0x0f,
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
        return new ServerSendFinishedMessageState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {

    }

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
        this.stateMachine = (ServerStateMachine) stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return true;
    }

}
