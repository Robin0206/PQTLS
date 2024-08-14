import client.PQTLSClient;
import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.FileInputStream;
import java.net.InetAddress;
import java.security.*;

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
                                PQTLSCipherSuite.TLS_ECDHE_KYBER_DILITHIUM_WITH_CHACHA20_POLY1305_SHA256,
                                Constants.MANDATORY_CIPHERSUITE
                        }
                ).curveIdentifiers(
                        new CurveIdentifier[]{
                                CurveIdentifier.secp384r1,
                                CurveIdentifier.secp256r1
                        }
                ).port(4443)
                .truststore(trustStore)
                .address(InetAddress.getByName("localhost"))
                .build();
        client.printApplicationSecrets();
    }
}
