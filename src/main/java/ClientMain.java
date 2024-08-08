import client.PQTLSClient;
import crypto.CryptographyModule;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;

public class ClientMain {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException {
        KeyPair sphincsKeyPair = CryptographyModule.keys.generateSPHINCSKeyPair();
        KeyPair dilithiumKeyPair = CryptographyModule.keys.generateDilithiumKeyPair();
        X509CertificateHolder sphincsCertificate = CryptographyModule.certificate.generateSelfSignedTestCertificate(sphincsKeyPair, "SPHINCSPlus");
        X509CertificateHolder dilithiumCertificate = CryptographyModule.certificate.generateSelfSignedTestCertificate(dilithiumKeyPair, "Dilithium");
        ArrayList<X509CertificateHolder> trustedCerts = new ArrayList<>();
        trustedCerts.add(sphincsCertificate);
        trustedCerts.add(dilithiumCertificate);
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
                .trustedCertificates(trustedCerts)
                .address(InetAddress.getByName("localhost"))
                .build();
    }
}
