package messages.implementations;

import messages.PQTLSMessage;


public class NullMessage implements PQTLSMessage {
    @Override
    public byte[] getBytes() {
        return new byte[]{(byte) 0xff};
    }

    @Override
    public void printVerbose() {
        System.out.println("====================================Null Message====================================");
    }

    @Override
    public boolean equals(PQTLSMessage message) {
        NullMessage castMessage = (NullMessage) message;
        return true;
    }
}
