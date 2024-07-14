package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.CertificateMessage;
import messages.implementations.CertificateVerifyMessage;
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

public class SendCertificateVerifyState extends State {

    private ServerStateMachine stateMachine;
    byte[] signature;
    byte[] messagesToSign;
    private PrivateKey privateKey;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        determinePrivateKeyToUse();
        setMessagesToSign();
        setSignature();
    }

    private void setMessagesToSign() {
        ArrayList<Byte> messagesConcatenated = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            for(Byte b : stateMachine.messages.get(i).getBytes()){
                messagesConcatenated.add(b);
            }
        }
        messagesToSign = ByteUtils.toByteArray(messagesConcatenated);
        stateMachine.concatenatedBytesForSignature = ByteUtils.toByteArray(messagesConcatenated);
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
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return new WrappedRecord(
                new CertificateVerifyMessage(signature, true),
                (byte) 0x0f,
                CryptographyModule.keys.byteArrToSymmetricKey(
                        stateMachine.sharedSecret.getServerHandShakeSecret(),
                        stateMachine.getPreferredSymmetricAlgorithm()
                ),
                stateMachine.sharedSecret.getServerHandShakeIVAndIncrement(),
                stateMachine.preferredCipherSuite
        );
    }

    @Override
    public State next() {
        return null;
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
