package messages.implementations;

import messages.PQTLSMessage;

//TODO
public class CertificateMessage implements PQTLSMessage {
    public CertificateMessage(byte[] decryptedMessageBytes) {
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public void printVerbose() {

    }
}
