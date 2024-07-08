package messages.implementations;

import messages.PQTLSMessage;

public class NullMessage implements PQTLSMessage {
    @Override
    public byte[] getBytes() {
        return new byte[]{0x00, (byte) 0xff};
    }

    @Override
    public void printVerbose() {
        System.out.println("====================================Null Message====================================");
    }
}
