package Server;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;


public class PQTLSServer {
    private Socket clientSocket;
    protected ServerSocket serverSocket;
    protected ServerHandshakeConnection handshakeConnection;
    protected ServerPSKConnection pskConnection;


    private PQTLSServer(){}

    private PQTLSServer(PQTLSServerBuilder builder) throws IOException {
        this.serverSocket = new ServerSocket(builder.port);
        this.clientSocket = this.serverSocket.accept();
    }

    public static class PQTLSServerBuilder{
        private int port;
        private CipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private boolean curveIdentifiersSet = false;
        private boolean portSet = false;
        private boolean cipherSuitesSet = false;

        public PQTLSServerBuilder port(int port){
            this.port = port;
            this.portSet = true;
            return this;
        }
        public PQTLSServerBuilder  cipherSuites(CipherSuite[] cipherSuites){
            this.cipherSuites = cipherSuites;
            this.cipherSuitesSet = true;
            return this;
        }
        public PQTLSServerBuilder supportedCurves(CurveIdentifier[] curveIdentifiers){
            this.curveIdentifiers = curveIdentifiers;
            this.curveIdentifiersSet = true;
            return this;
        }
        public PQTLSServer build() throws IOException {
            throwExceptionIfNecessary();
            return new PQTLSServer(this);
        }

        private void throwExceptionIfNecessary() {
            if(!portSet){
                throw new IllegalStateException("Port must be set before calling build()");
            }
            if(!cipherSuitesSet){
                throw new IllegalStateException("Ciphersuites must be set before calling build()");
            }
            if(!curveIdentifiersSet){
                throw new IllegalStateException("Supported curves must be set before calling build()");
            }
        }
    }
}
