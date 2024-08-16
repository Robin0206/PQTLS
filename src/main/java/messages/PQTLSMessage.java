package messages;

import java.security.cert.CertificateException;

/**
 * @author Robin Kroker
 */
public interface PQTLSMessage {
    byte[] getBytes();
    void printVerbose() throws CertificateException;
    boolean equals(PQTLSMessage message);
}
