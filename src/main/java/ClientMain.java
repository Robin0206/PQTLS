import client.PQTLSClient;
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
import java.net.InetAddress;
import java.security.*;

//Little test program that shows the usage of the PQTLSClient class

public class ClientMain {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream storeIn = new FileInputStream("clientTrustStore.jks");
        trustStore.load(storeIn, "password".toCharArray());
        PQTLSClient client = new PQTLSClient.PQTLSClientBuilder()
                .cipherSuites(
                        new PQTLSCipherSuite[]{
                                PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_CHACHA20_POLY1305_SHA256,
                                Constants.MANDATORY_CIPHERSUITE
                        }
                ).curveIdentifiers(
                        new CurveIdentifier[]{
                                Constants.MANDATORY_CURVE,
                                CurveIdentifier.secp384r1,
                                CurveIdentifier.secp521r1
                        }
                ).port(4443)
                .truststore(trustStore)
                .address(InetAddress.getByName("localhost"))
                .build();

        String message = "Hello Server";
        TlsProtocol protocol = client.getProtocol();
        BufferedReader reader = new BufferedReader(new InputStreamReader(protocol.getInputStream()));
        PrintWriter writer = new PrintWriter(protocol.getOutputStream(), true);
        writer.println(message);
        System.out.println("Sent: " + message);
        String response = reader.readLine();
        System.out.println("Server response: " + response);
    }
}
