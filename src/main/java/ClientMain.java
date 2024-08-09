import client.PQTLSClient;
import crypto.CryptographyModule;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;

public class ClientMain {
    public static void main(String[] args) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream storeIn = new FileInputStream("clientTrustStore.jks");
        trustStore.load(storeIn, "password".toCharArray());
        PQTLSClient client = new PQTLSClient.PQTLSClientBuilder()
                .cipherSuites(
                        new CipherSuite[]{
                                Constants.MANDATORY_CIPHERSUITE,
                                CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
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
    }
}
