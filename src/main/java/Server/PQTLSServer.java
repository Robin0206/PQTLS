package Server;

import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import statemachines.server.ServerStateMachine;

import java.io.Closeable;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;

/**
 * @author Robin Kroker
 * Uses fluent builder pattern
 */
public class PQTLSServer implements Closeable {
    private Socket clientSocket;
    protected ServerSocket serverSocket;
    protected ServerHandshakeConnection handshakeConnection;
    protected ServerPSKConnection pskConnection;
    protected TlsServerProtocol protocol;

    /**
     * Private constructor, that's used by the fluent builder
     * @param builder
     * @throws Exception
     */
    private PQTLSServer(PQTLSServerBuilder builder) throws Exception {
        this.serverSocket = new ServerSocket(builder.port);
        this.clientSocket = this.serverSocket.accept();
        this.handshakeConnection = new ServerHandshakeConnection(
                buildStateMachine(builder),
                clientSocket,
                this,
                builder.printHandShakeMessages
        );
        this.handshakeConnection.doHandshake();
        this.pskConnection = new ServerPSKConnection(
                new BcTlsCrypto(),
                handshakeConnection.getStateMachine().getSharedSecret()
        );
        protocol = new TlsServerProtocol(clientSocket.getInputStream(), clientSocket.getOutputStream());
        protocol.accept(this.pskConnection);
    }
    /**
     * Returns the TlsServerProtocol object that's meant to be used for communication after the handshake
     * @return TlsServerProtocol
     */
    public TlsServerProtocol getProtocol(){
        return protocol;
    }

    /**
     * Builds the statemachine that's used b the handshake connection
     * @param builder
     * @return
     * @throws Exception
     */
    private ServerStateMachine buildStateMachine(PQTLSServerBuilder builder) throws Exception {
        return new ServerStateMachine.ServerStateMachineBuilder()
                .supportedCurves(builder.curveIdentifiers)
                .certificateChains(builder.certificateChains)
                .signatureKeyPairs(builder.keyPairs)
                .cipherSuites(builder.cipherSuites)
                .build();
    }
    /**
     * Prints the Client and Server Application Secret that's calculated by the Shared Secret holder
     */
    public void printApplicationSecrets() {
        handshakeConnection.getStateMachine().getSharedSecret().printApplicationTrafficSecrets();
    }

    @Override
    public void close() throws IOException {
        this.protocol.close();
        this.clientSocket.close();
        this.serverSocket.close();
    }
    /**
     * @author Robin Kroker
     */
    public static class PQTLSServerBuilder {
        private int port;
        private PQTLSCipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private boolean curveIdentifiersSet = false;
        private boolean portSet = false;
        private boolean cipherSuitesSet = false;
        private ArrayList<X509CertificateHolder[]> certificateChains;
        private KeyPair[] keyPairs;
        private boolean printHandShakeMessages = false;
        /**
         * if this method is called, the resulting PQTLSServer will print handShakeMessages
         * @return PQTLSClientBuilder
         */
        public PQTLSServerBuilder printHandShakeMessages() {
            this.printHandShakeMessages = true;
            return this;
        }
        /**
         * Sets the port
         * @return PQTLSClientBuilder
         */
        public PQTLSServerBuilder port(int port) {
            this.port = port;
            this.portSet = true;
            return this;
        }
        /**
         * Sets the cipher suites
         * @param cipherSuites
         * @return
         */
        public PQTLSServerBuilder cipherSuites(PQTLSCipherSuite[] cipherSuites) {
            this.cipherSuites = cipherSuites;
            this.cipherSuitesSet = true;
            return this;
        }
        /**
         * Sets the curve identifiers
         * @param curveIdentifiers
         * @return PQTLSClientBuilder
         */
        public PQTLSServerBuilder curveIdentifiers(CurveIdentifier[] curveIdentifiers) {
            this.curveIdentifiers = curveIdentifiers;
            this.curveIdentifiersSet = true;
            return this;
        }
        /**
         * sets the keyStore that's used for the handshake
         * @return PQTLSClientBuilder
         */
        public PQTLSServerBuilder keyStore(KeyStore keyStore, char[] password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateEncodingException, IOException {
            ArrayList<KeyPair> keyPairBuffer = new ArrayList<>();
            certificateChains = new ArrayList<>();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String currentAlias = aliases.nextElement();
                Certificate[] currentChain = keyStore.getCertificateChain(currentAlias);
                X509CertificateHolder[] holders = new X509CertificateHolder[currentChain.length];
                for (int i = 0; i < currentChain.length; i++) {
                    holders[i] = new X509CertificateHolder(currentChain[0].getEncoded());
                }
                certificateChains.add(holders);
                keyPairBuffer.add(
                        new KeyPair(
                                currentChain[0].getPublicKey(),
                                (PrivateKey) keyStore.getKey(currentAlias, password)
                        )
                );
            }
            keyPairs = new KeyPair[certificateChains.size()];
            for (int i = 0; i < keyPairBuffer.size(); i++) {
                keyPairs[i] = keyPairBuffer.get(i);
            }
            return this;
        }
        /**
         * Fluent Builder build() method
         * @return PQTLSClient
         */
        public PQTLSServer build() throws Exception {
            throwExceptionIfNecessary();
            return new PQTLSServer(this);
        }
        /**
         * Throws an exception if not all necessary builder methods are called before the final build();
         */
        private void throwExceptionIfNecessary() {
            if (!portSet) {
                throw new IllegalStateException("Port must be set before calling build()");
            }
            if (!cipherSuitesSet) {
                throw new IllegalStateException("Ciphersuites must be set before calling build()");
            }
            if (!curveIdentifiersSet) {
                throw new IllegalStateException("Supported curves must be set before calling build()");
            }
        }
    }
}
