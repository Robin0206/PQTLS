package messages.extensions;

public interface PQTLSExtension {
    public byte[] getByteRepresentation();
    public void printVerbose();
    public byte getIdentifier();
}
