package client;

import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tls.TlsClientProtocol;
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
/**
 * @author Robin Kroker
 */
public class PQTLSClient implements Closeable {
    ClientHandShakeConnection handShakeConnection;
    ClientPSKConnection pskConnection;
    Socket socket;
    TlsClientProtocol protocol;

    /**
     * Private constructor that's used by the fluent builder
     * @param pqtlsClientBuilder
     * @throws Exception
     */
    private PQTLSClient(PQTLSClientBuilder pqtlsClientBuilder) throws Exception {
        this.socket = new Socket(pqtlsClientBuilder.address, pqtlsClientBuilder.port);
        ClientStateMachine stateMachine = buildStateMachine(pqtlsClientBuilder);
        handShakeConnection = new ClientHandShakeConnection(stateMachine, socket, this, pqtlsClientBuilder.printHandShakeMessages);
        handShakeConnection.doHandshake();
        pskConnection = new ClientPSKConnection(handShakeConnection.getStateMachine().getSharedSecret());
        protocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
        protocol.connect(this.pskConnection);
    }

    /**
     * Returns the TlsClientProtocol object that's meant to be used for communication after the handshake
     * @return TlsClientProtocol
     */
    public TlsClientProtocol getProtocol(){
        return protocol;
    }

    /**
     * builds the statemachine that's used by the handshake connection
     * @param builder
     * @return ClientStateMachine
     */
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
        protocol.close();
        socket.close();
    }

    /**
     * Prints the Client and Server Application Secret that's calculated by the Shared Secret holder
     */
    public void printApplicationSecrets() {
        handShakeConnection.getStateMachine().getSharedSecret().printApplicationTrafficSecrets();
    }
    /**
     * @author Robin Kroker
     */
    public static class PQTLSClientBuilder {
        private PQTLSCipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private ArrayList<X509CertificateHolder> trustedCertificates;
        private int port;
        private InetAddress address;
        byte[] algIdentifiers;
        private boolean printHandShakeMessages = false;
        private boolean portSet = false;
        private boolean addressSet = false;
        private boolean trustedCertificatesSet = false;
        private boolean curveIdentifiersSet = false;
        private boolean cipherSuiteSet = false;

        /**
         * Sets the cipher suites
         * @param cipherSuites
         * @return
         */
        public PQTLSClientBuilder cipherSuites(PQTLSCipherSuite[] cipherSuites) {
            this.cipherSuites = cipherSuites;
            this.cipherSuiteSet = true;
            for (PQTLSCipherSuite c : cipherSuites) {
                if (c.toString().contains("DILITHIUM")) {
                    algIdentifiers = new byte[]{0, 1};// supports sphincs and dilithium
                    return this;
                }
            }
            // only supports sphincs
            algIdentifiers = new byte[]{0};
            return this;
        }

        /**
         * Sets the curve identifiers
         * @param curveIdentifiers
         * @return PQTLSClientBuilder
         */
        public PQTLSClientBuilder curveIdentifiers(CurveIdentifier[] curveIdentifiers) {
            this.curveIdentifiers = curveIdentifiers;
            this.curveIdentifiersSet = true;
            return this;
        }
        /**
         * if this method is called, the resulting PQTLSClient will print handShakeMessages
         * @return PQTLSClientBuilder
         */
        public PQTLSClientBuilder printHandShakeMessages() {
            this.printHandShakeMessages = true;
            return this;
        }
        /**
         * sets the trustStore that's used for the handshake
         * @return PQTLSClientBuilder
         */
        public PQTLSClientBuilder truststore(KeyStore keystore) throws KeyStoreException, CertificateEncodingException, IOException {
            this.trustedCertificates = extractCertsFromKeyStore(keystore);
            this.trustedCertificatesSet = true;
            return this;
        }

        /**
         * Sets the port
         * @return PQTLSClientBuilder
         */
        public PQTLSClientBuilder port(int port) {
            this.port = port;
            this.portSet = true;
            return this;
        }
        /**
         * Sets the address
         * @return PQTLSClientBuilder
         */
        public PQTLSClientBuilder address(InetAddress address) {
            this.address = address;
            this.addressSet = true;
            return this;
        }

        /**
         * Fluent Builder build() method
         * @return PQTLSClient
         */
        public PQTLSClient build() throws Exception {
            throwExceptionIfNecessary();
            return new PQTLSClient(this);
        }

        /**
         * Throws an exception if not all necessary builder methods are called before the final build();
         */
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

    /**
     * Private method to extract the trusted certificates from the keystore
     * @param keystore
     * @return
     * @throws KeyStoreException
     * @throws CertificateEncodingException
     * @throws IOException
     */
    private static ArrayList<X509CertificateHolder> extractCertsFromKeyStore(KeyStore keystore) throws KeyStoreException, CertificateEncodingException, IOException {
        ArrayList<X509CertificateHolder> result = new ArrayList<>();
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            result.add(new X509CertificateHolder(keystore.getCertificate(aliases.nextElement()).getEncoded()));
        }
        return result;
    }
}
