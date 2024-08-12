import Server.PQTLSServer;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.FileInputStream;
import java.security.*;

public class ServerMain {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream storeIn = new FileInputStream("serverKeyStore.jks");
        keyStore.load(storeIn, "password".toCharArray());
        PQTLSServer server = new PQTLSServer.PQTLSServerBuilder()
                .cipherSuites(
                        new CipherSuite[]{
                                Constants.MANDATORY_CIPHERSUITE,
                                CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_CHACHA20_POLY1305_SHA384,
                                CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_SPHINCS_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_CHACHA20_POLY1305_SHA384
                        }
                )
                .port(4443)
                .curveIdentifiers(
                        new CurveIdentifier[]{
                                CurveIdentifier.secp384r1,
                                CurveIdentifier.secp256r1
                        }
                )
                .keyStore(keyStore, "password".toCharArray())
                .build();
        server.printApplicationSecrets();

    }
}
