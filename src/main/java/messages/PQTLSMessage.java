package messages;

import java.security.cert.CertificateException;

public interface PQTLSMessage {
    public byte[] getBytes();
    public void printVerbose() throws CertificateException;
    public boolean equals(PQTLSMessage message);
}
