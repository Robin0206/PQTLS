package messages.extensions;

public interface PQTLSExtension {
    public byte[] getBytes();
    public PQTLSExtension fromBytes();
    public PQTLSExtension printVerbose();
}
