package client;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import jdk.jshell.spi.ExecutionControl;
import org.bouncycastle.cert.X509CertificateHolder;
import statemachines.client.ClientStateMachine;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;

public class PQTLSClient {
    ClientHandShakeConnection handShakeConnection;
    ClientPSKConnection pskConnection;
    Socket socket;

    private PQTLSClient(PQTLSClientBuilder pqtlsClientBuilder) throws IOException {
        this.socket = new Socket(pqtlsClientBuilder.address, pqtlsClientBuilder.port);
        ClientStateMachine stateMachine = buildStateMachine(pqtlsClientBuilder);
        handShakeConnection = new ClientHandShakeConnection(stateMachine, socket);
        pskConnection = new ClientPSKConnection(handShakeConnection.getStateMachine().getSharedSecret(), socket);
    }



    private PQTLSClient(){}

    //TODO
    private ClientStateMachine buildStateMachine(PQTLSClientBuilder pqtlsClientBuilder) {
        return null;
    }

    public static class PQTLSClientBuilder{
        private CipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private byte[] algIdentifiers;
        private ArrayList<X509CertificateHolder> trustedCertificates;
        private int port;
        private InetAddress address;
        private boolean portSet = false;
        private boolean addressSet = false;
        private boolean algIdentifiersSet = false;
        private boolean trustedCertificatesSet = false;
        private boolean curveIdentifiersSet = false;
        private boolean cipherSuiteSet = false;

        public PQTLSClientBuilder cipherSuites(CipherSuite[] cipherSuites){
            this.cipherSuites = cipherSuites;
            this.cipherSuiteSet = true;
            return this;
        }

        public PQTLSClientBuilder curveIdentifiers(CurveIdentifier[] curveIdentifiers){
            this.curveIdentifiers = curveIdentifiers;
            this.curveIdentifiersSet = true;
            return this;
        }

        public PQTLSClientBuilder supportedSignatureAlgorithms(byte[] algIdentifiers){
            this.algIdentifiers = algIdentifiers;
            this.algIdentifiersSet = true;
            return this;
        }

        public PQTLSClientBuilder trustedCertificates(ArrayList<X509CertificateHolder> trustedCertificates){
            this.trustedCertificates = trustedCertificates;
            this.trustedCertificatesSet = true;
            return this;
        }
        
        public PQTLSClientBuilder port(int port){
            this.port = port;
            this.portSet = true;
            return this;
        }

        public PQTLSClientBuilder address(InetAddress address){
            this.address = address;
            this.addressSet = true;
            return this;
        }

        public PQTLSClient build() throws IOException {
            throwExceptionIfNecessary();
            return new PQTLSClient(this);
        }

        private void throwExceptionIfNecessary() {
            if(!portSet){
                throw new IllegalStateException("Port must be set before building");
            }
            if(!addressSet){
                throw new IllegalStateException("Address must be set before building");
            }
            if(!algIdentifiersSet){
                throw new IllegalStateException("AlgIdentifier must be set before building");
            }
            if(!curveIdentifiersSet){
                throw new IllegalStateException("CurveIdentifiers must be set before building");
            }
            if(!cipherSuiteSet){
                throw new IllegalStateException("CipherSuites must be set before building");
            }
        }
    }
}
