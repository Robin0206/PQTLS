package messages.extensions;
/**
 * @author Robin Kroker
 */
public interface PQTLSExtension {
    byte[] getByteRepresentation();
    void printVerbose();
    byte getIdentifier();
}
