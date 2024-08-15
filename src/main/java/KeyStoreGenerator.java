import crypto.CryptographyModule;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

//Little program that generates the key and trustStores

public class KeyStoreGenerator {

    private static X509CertificateHolder[] rootCaCerts;
    private static KeyPair[] rootKeyPairs;
    private static X509CertificateHolder[][] serverCertificateChains;
    private static X509CertificateHolder[] clientTrustedCertificates;
    static KeyStore clientTrustStore;
    private static KeyStore serverKeyStore;


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleProvider());
        rootKeyPairs = generateRootCaKeyPairs();
        rootCaCerts = generateRootCaCerts(rootKeyPairs);
        serverCertificateChains = generateServerCertificateChains(rootCaCerts);
        clientTrustedCertificates = rootCaCerts;
        clientTrustStore = generateClientTrustStore(clientTrustedCertificates);
        serverKeyStore = generateServerKeyStore(serverCertificateChains, rootKeyPairs);
        FileOutputStream f1 = new FileOutputStream("serverKeyStore.jks");
        FileOutputStream f2 = new FileOutputStream("clientTrustStore.jks");
        clientTrustStore.store(f2, "password".toCharArray());
        serverKeyStore.store(f1, "password".toCharArray());

    }

    private static KeyStore generateServerKeyStore(X509CertificateHolder[][] serverCertificateChains, KeyPair[] rootKeyPairs) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore result = KeyStore.getInstance("JKS");
        result.load(null, null);
        Certificate[][] chains = new Certificate[][]{
                {
                        CryptographyModule.certificate.holderToCertificate(serverCertificateChains[0][0]),
                        CryptographyModule.certificate.holderToCertificate(serverCertificateChains[0][1])
                },
                {
                        CryptographyModule.certificate.holderToCertificate(serverCertificateChains[1][0]),
                },
        };
        result.setKeyEntry("SPCert", rootKeyPairs[0].getPrivate(), "password".toCharArray(), chains[0]);
        result.setKeyEntry("DICert", rootKeyPairs[1].getPrivate(), "password".toCharArray(), chains[1]);
        return result;
    }

    private static KeyStore generateClientTrustStore(X509CertificateHolder[] clientTrustedCertificates) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore result = KeyStore.getInstance(KeyStore.getDefaultType());
        result.load(null, "password".toCharArray());
        result.setCertificateEntry(
                "SPCert",
                CryptographyModule.certificate.holderToCertificate(clientTrustedCertificates[0])
        );
        result.setCertificateEntry(
                "DICert",
                CryptographyModule.certificate.holderToCertificate(clientTrustedCertificates[1])
        );
        return result;
    }


    private static X509CertificateHolder[][] generateServerCertificateChains(X509CertificateHolder[] rootCaCerts) throws Exception {
        X509CertificateHolder intermediateCert = generateCertificate(
                CryptographyModule.certificate.holderToCertificate(rootCaCerts[0]),
                "IntermediateTest",
                rootKeyPairs[0]
        );
        return new X509CertificateHolder[][]{
                {intermediateCert, rootCaCerts[0]},
                {rootCaCerts[1]}
        };
    }

    private static KeyPair[] generateRootCaKeyPairs() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair[] result = new KeyPair[2];
        result[0] = CryptographyModule.keys.generateSPHINCSKeyPair();
        result[1] = CryptographyModule.keys.generateDilithiumKeyPair();
        return result;
    }

    private static X509CertificateHolder[] generateRootCaCerts(KeyPair[] kp) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        X509CertificateHolder[] result = new X509CertificateHolder[2];
        result[0] = CryptographyModule.certificate.generateSelfSignedTestCertificate(kp[0], "SPHINCSPlus");
        result[1] = CryptographyModule.certificate.generateSelfSignedTestCertificate(kp[1], "Dilithium");
        return result;
    }

    private static X509CertificateHolder generateCertificate(X509Certificate issuerCert, String dnName, KeyPair keyPair) throws Exception {
        X500Name name = new X500Name("CN=TestIntermediate");
        PrivateKey privateKey = keyPair.getPrivate();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerCert,
                BigInteger.valueOf(0),
                new Date(),
                new Date(),
                X500Name.getInstance(name),
                CryptographyModule.keys.generateSPHINCSKeyPair().getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SPHINCSPlus")
                .setProvider("BCPQC")
                .build(privateKey);
        return certBuilder.build(signer);
    }

}

