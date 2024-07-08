package messages.implementations;

import messages.PQTLSMessage;

//TODO
public class EncryptedExtensions implements PQTLSMessage{

    public EncryptedExtensions(byte[] messageBytes) {
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public void printVerbose() {

    }
}
