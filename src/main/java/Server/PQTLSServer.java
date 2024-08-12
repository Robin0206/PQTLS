package Server;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import statemachines.server.ServerStateMachine;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;


public class PQTLSServer {
    private Socket clientSocket;
    protected ServerSocket serverSocket;
    protected ServerHandshakeConnection handshakeConnection;
    protected ServerPSKConnection pskConnection;

    private PQTLSServer() {

    }

    private PQTLSServer(PQTLSServerBuilder builder) throws Exception {
        this.serverSocket = new ServerSocket(builder.port);
        this.clientSocket = this.serverSocket.accept();
        this.handshakeConnection = new ServerHandshakeConnection(
                buildStateMachine(builder),
                serverSocket,
                clientSocket,
                this
        );
        this.handshakeConnection.doHandshake();
    }

    private ServerStateMachine buildStateMachine(PQTLSServerBuilder builder) throws Exception {
        return new ServerStateMachine.ServerStateMachineBuilder()
                .supportedCurves(builder.curveIdentifiers)
                .certificateChains(builder.certificateChains)
                .signatureKeyPairs(builder.keyPairs)
                .cipherSuites(builder.cipherSuites)
                .build();
    }

    public void printApplicationSecrets() {
        handshakeConnection.getStateMachine().getSharedSecret().printApplicationTrafficSecrets();
    }

    public static class PQTLSServerBuilder {
        private int port;
        private CipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private boolean curveIdentifiersSet = false;
        private boolean portSet = false;
        private boolean cipherSuitesSet = false;
        private ArrayList<X509CertificateHolder[]> certificateChains;
        private KeyPair[] keyPairs;

        public PQTLSServerBuilder port(int port) {
            this.port = port;
            this.portSet = true;
            return this;
        }

        public PQTLSServerBuilder cipherSuites(CipherSuite[] cipherSuites) {
            this.cipherSuites = cipherSuites;
            this.cipherSuitesSet = true;
            return this;
        }

        public PQTLSServerBuilder curveIdentifiers(CurveIdentifier[] curveIdentifiers) {
            this.curveIdentifiers = curveIdentifiers;
            this.curveIdentifiersSet = true;
            return this;
        }

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

        public PQTLSServer build() throws Exception {
            throwExceptionIfNecessary();
            return new PQTLSServer(this);
        }

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
