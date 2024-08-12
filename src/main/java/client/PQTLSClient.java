package client;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import statemachines.client.ClientStateMachine;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;

public class PQTLSClient implements Closeable {
    ClientHandShakeConnection handShakeConnection;
    ClientPSKConnection pskConnection;
    Socket socket;

    private PQTLSClient(PQTLSClientBuilder pqtlsClientBuilder) throws Exception {
        this.socket = new Socket(pqtlsClientBuilder.address, pqtlsClientBuilder.port);
        ClientStateMachine stateMachine = buildStateMachine(pqtlsClientBuilder);
        handShakeConnection = new ClientHandShakeConnection(stateMachine, socket, this);
        pskConnection = new ClientPSKConnection(handShakeConnection.getStateMachine().getSharedSecret(), socket);
        handShakeConnection.doHandshake();
    }

    private PQTLSClient() {}

    private ClientStateMachine buildStateMachine(PQTLSClientBuilder builder) {
        return new ClientStateMachine.ClientStateMachineBuilder()
                .cipherSuites(builder.cipherSuites)
                .curveIdentifiers(builder.curveIdentifiers)
                .trustedCertificates(builder.trustedCertificates)
                .numberOfCurvesSendByClientHello(builder.curveIdentifiers.length)
                .extensionIdentifiers(new byte[]{
                                Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS,
                                Constants.EXTENSION_IDENTIFIER_KEY_SHARE,
                                Constants.EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS
                        }
                )
                .build();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    public void printApplicationSecrets() {
        handShakeConnection.getStateMachine().getSharedSecret().printApplicationTrafficSecrets();
    }

    public static class PQTLSClientBuilder {
        private CipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private byte[] algIdentifiers;
        private ArrayList<X509CertificateHolder> trustedCertificates;
        private int port;
        private InetAddress address;
        private boolean portSet = false;
        private boolean addressSet = false;
        private boolean trustedCertificatesSet = false;
        private boolean curveIdentifiersSet = false;
        private boolean cipherSuiteSet = false;

        public PQTLSClientBuilder cipherSuites(CipherSuite[] cipherSuites) {
            this.cipherSuites = cipherSuites;
            this.cipherSuiteSet = true;
            for (CipherSuite c : cipherSuites) {
                if (c.toString().contains("DILITHIUM")) {
                    this.algIdentifiers = new byte[]{0, 1};// supports sphincs and dilithium
                    return this;
                }
            }
            // only supports sphincs
            this.algIdentifiers = new byte[]{0};
            return this;
        }

        public PQTLSClientBuilder curveIdentifiers(CurveIdentifier[] curveIdentifiers) {
            this.curveIdentifiers = curveIdentifiers;
            this.curveIdentifiersSet = true;
            return this;
        }

        public PQTLSClientBuilder truststore(KeyStore keystore) throws KeyStoreException, CertificateEncodingException, IOException {
            this.trustedCertificates = extractCertsFromKeyStore(keystore);
            this.trustedCertificatesSet = true;
            return this;
        }


        public PQTLSClientBuilder port(int port) {
            this.port = port;
            this.portSet = true;
            return this;
        }

        public PQTLSClientBuilder address(InetAddress address) {
            this.address = address;
            this.addressSet = true;
            return this;
        }


        public PQTLSClient build() throws Exception {
            throwExceptionIfNecessary();
            return new PQTLSClient(this);
        }

        private void throwExceptionIfNecessary() {
            if (!portSet) {
                throw new IllegalStateException("Port must be set before building");
            }
            if (!addressSet) {
                throw new IllegalStateException("Address must be set before building");
            }
            if (!curveIdentifiersSet) {
                throw new IllegalStateException("CurveIdentifiers must be set before building");
            }
            if (!cipherSuiteSet) {
                throw new IllegalStateException("CipherSuites must be set before building");
            }
            if (!trustedCertificatesSet) {
                throw new IllegalStateException("trustedCertificates must be set before building");
            }
        }
    }

    private static ArrayList<X509CertificateHolder> extractCertsFromKeyStore(KeyStore keystore) throws KeyStoreException, CertificateEncodingException, IOException {
        ArrayList<X509CertificateHolder> result = new ArrayList<>();
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            result.add(new X509CertificateHolder(keystore.getCertificate(aliases.nextElement()).getEncoded()));
        }
        return result;
    }
}
