package messages.implementations;

import messages.PQTLSMessage;

public class FinishedMessage implements PQTLSMessage {
    public FinishedMessage(byte[] decryptedMessageBytes) {
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
