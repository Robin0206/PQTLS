package messages.implementations;

import messages.PQTLSMessage;

//TODO
public class CertificateVerifyMessage implements PQTLSMessage {
    public CertificateVerifyMessage(byte[] decryptedMessageBytes) {
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public void printVerbose() {

    }

    @Override
    public boolean equals(PQTLSMessage message) {
        return false;
    }
}
