package messages.implementations;

import messages.PQTLSMessage;
import misc.ByteUtils;

import java.util.Arrays;

//TODO
public class CertificateVerifyMessage implements PQTLSMessage {
    private final byte[] signature;

    public CertificateVerifyMessage(byte[] messageBytes) {
        this.signature = new byte[messageBytes.length - 4];
        System.arraycopy(
                messageBytes,
                4,
                this.signature,
                0,
                this.signature.length
        );
    }
    public CertificateVerifyMessage(byte[] signatureBytes, boolean bytesOnlyContainSignature) {
        this.signature = signatureBytes.clone();
    }

    @Override
    public byte[] getBytes() {
        byte[] byteRepresentation = new byte[signature.length + 4];
        byte[] numOfFollowingBytes = ByteUtils.intToByteArray3(signature.length);
        System.arraycopy(
                signature,
                0,
                byteRepresentation,
                4,

                signature.length
        );
        System.arraycopy(
                numOfFollowingBytes,
                0,
                byteRepresentation,
                1,
                numOfFollowingBytes.length
        );
        byteRepresentation[0] = 0x0f;
        return byteRepresentation;
    }

    @Override
    public void printVerbose() {

    }

    @Override
    public boolean equals(PQTLSMessage messageToCast) {
        CertificateVerifyMessage message = (CertificateVerifyMessage) messageToCast;
        return Arrays.equals(message.signature, signature);
    }

    public byte[] getSignature() {
        return signature.clone();
    }
}
