import Server.PQTLSServer;
import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.tls.TlsProtocol;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.*;

//Little test program that shows the usage of the PQTLSServer class

public class ServerMain {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream storeIn = new FileInputStream("serverKeyStore.jks");
        keyStore.load(storeIn, "password".toCharArray());
        PQTLSServer server = new PQTLSServer.PQTLSServerBuilder()
                .cipherSuites(
                        new PQTLSCipherSuite[]{
                                PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_CHACHA20_POLY1305_SHA256,
                                Constants.MANDATORY_CIPHERSUITE
                        }
                )
                .port(4443)
                .curveIdentifiers(
                        new CurveIdentifier[]{
                                Constants.MANDATORY_CURVE,
                                CurveIdentifier.secp384r1
                        }
                )
                .keyStore(keyStore, "password".toCharArray())
                .build();

        TlsProtocol protocol = server.getProtocol();
        String message = "Hello Client";
        BufferedReader reader = new BufferedReader(new InputStreamReader(protocol.getInputStream()));
        PrintWriter writer = new PrintWriter(protocol.getOutputStream(), true);
        String clientMessage = reader.readLine();
        System.out.println("recieved: " +clientMessage);
        writer.println(message);
        System.out.println("sent back: " + message);
    }
}
