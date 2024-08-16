package messages.implementations;

import crypto.CryptographyModule;
import crypto.enums.PQTLSCipherSuite;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class WrappedRecordTest {
    static WrappedRecord wrappedRecord1;
    static WrappedRecord wrappedRecord2;
    static SecureRandom rand;
    static byte[][]keys;
    static byte[] iv;
    static ArrayList<X509CertificateHolder[]> certificateHolders;
    @BeforeAll
    public static void initialize(){
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        Security.addProvider(new BouncyCastleProvider());
        rand = new SecureRandom();
        keys = new byte[100][32];
        for (byte[] key : keys) {
            rand.nextBytes(key);
        }
        certificateHolders = new ArrayList<>();
        iv = new byte[12];
    }

    @Test
    void randomGeneratingOfMessagesShouldNotThrow(){
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("randomGeneratingOfMessagesShouldNotThrow: " + i + " of " + "100");
                setWrappedRecord1Random(Math.abs(rand.nextInt())% keys.length, rand.nextBoolean() ? "AES" : "ChaCha20");
            }
        });
    }

    @Test
    void testGenerationFromBytes(){
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("testGenerationFromBytes: " + i + " of " + "100");
                int usedKeyIndex = Math.abs(rand.nextInt())% keys.length;
                String usedKeyAlg = rand.nextBoolean() ? "AES" : "ChaCha20";
                setWrappedRecord1Random(usedKeyIndex, usedKeyAlg);
                wrappedRecord2 = new WrappedRecord(
                        wrappedRecord1.getBytes(),
                        CryptographyModule.keys.byteArrToSymmetricKey(keys[usedKeyIndex], usedKeyAlg),
                        iv,
                        usedKeyAlg.equals("AES") ?
                                PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384 :
                                PQTLSCipherSuite.TLS_ECDHE_KYBER_DILITHIUM_WITH_CHACHA20_POLY1305_SHA256
                );
                assertTrue(wrappedRecord1.equals(wrappedRecord2));
            }
        });
    }
    public static void setWrappedRecord1Random(int keyIndex, String symmetricAlgorithm) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, NoSuchProviderException, InvalidKeyException, OperatorCreationException {
        PQTLSMessage randomMessageToWrap = generateRandomMessageToWrap();
        byte recordType = getRecordType(randomMessageToWrap);
        wrappedRecord1 = new WrappedRecord(
                randomMessageToWrap,
                recordType,
                CryptographyModule.keys.byteArrToSymmetricKey(keys[keyIndex], symmetricAlgorithm),
                iv,
                symmetricAlgorithm.equals("AES") ?
                        PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384 :
                        PQTLSCipherSuite.TLS_ECDHE_KYBER_DILITHIUM_WITH_CHACHA20_POLY1305_SHA256
        );
    }

    private static byte getRecordType(PQTLSMessage randomMessageToWrap) {
        return randomMessageToWrap.getBytes()[0];
    }

    private static PQTLSMessage generateRandomMessageToWrap() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException {
        return switch (Math.abs(rand.nextInt()) % 4) {
            case 0 -> new EncryptedExtensions(generateRandomExtensionArray());
            case 1 -> new CertificateMessage(generateRandomCertificateArray());
            case 2 -> new NullMessage();
            default -> new NullMessage();
        };
    }

    static HelloMessage generateRandomHelloMessage() {
        SecureRandom rand = new SecureRandom();
        PQTLSCipherSuite[] cipherSuites = new PQTLSCipherSuite[1+ Math.abs(rand.nextInt())%4];
        for (int i = 0; i < cipherSuites.length; i++) {
            cipherSuites[i] = PQTLSCipherSuite.values()[Math.abs(rand.nextInt())% PQTLSCipherSuite.values().length];
        }
        byte[] sessionID = new byte[Math.abs(rand.nextInt())%40];
        Arrays.fill(sessionID, (byte) 1);
        byte[] random = new byte[Constants.HELLO_MESSAGE_RANDOM_LENGTH];
        rand.nextBytes(random);
        boolean usesKeyShareExtension = rand.nextBoolean();
        boolean usesSignatureExtension = rand.nextBoolean();

        byte[][] keys = new byte[2 + Math.abs(rand.nextInt())%2][];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = new byte[rand.nextBoolean() ? 1088: 168];
            rand.nextBytes(keys[i]);
        }
        //generate Extensions
        KeyShareExtension keyShare = new KeyShareExtension(
                keys
        );
        SignatureAlgorithmsExtension sig = new SignatureAlgorithmsExtension(new byte[]{
                Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM,
                Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS
        });
        PQTLSExtension[] extensions;
        if(usesKeyShareExtension && usesSignatureExtension){
            extensions = new PQTLSExtension[]{
                    keyShare, sig
            };
        }else if(usesKeyShareExtension){
            extensions = new PQTLSExtension[]{keyShare};
        }else{
            extensions = new PQTLSExtension[]{sig};
        }
        return new HelloMessage.HelloBuilder()
                .random(random)
                .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO)
                .cipherSuites(cipherSuites)
                .LegacyVersion(new byte[]{0x3, 0x3})
                .extensions(extensions)
                .sessionID(sessionID)
                .build();
    }

    private static X509CertificateHolder[] generateRandomCertificateArray() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        X509CertificateHolder[] certificates = new X509CertificateHolder[Math.abs(rand.nextInt())%10 + 1];
        for(int i = 0; i < certificates.length; i++){
            String signatureAlgorithm = rand.nextInt()%2 == 0 ? "SPHINCSPlus" : "Dilithium";
            certificates[i] = CryptographyModule.certificate.generateSelfSignedTestCertificate(signatureAlgorithm);
        }
        return certificates;
    }

    private static PQTLSExtension[] generateRandomExtensionArray() {
        boolean usesKeyShareExtension = rand.nextBoolean();
        boolean usesSignatureExtension = rand.nextBoolean();
        //generate Extensions
        KeyShareExtension keyShare = new KeyShareExtension(
                keys
        );
        SignatureAlgorithmsExtension sig = new SignatureAlgorithmsExtension(new byte[]{
                Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM,
                Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS
        });
        PQTLSExtension[] extensions;
        if(usesKeyShareExtension && usesSignatureExtension){
            extensions = new PQTLSExtension[]{
                    keyShare, sig
            };
        }else if(usesKeyShareExtension){
            extensions = new PQTLSExtension[]{keyShare};
        }else if(usesSignatureExtension){
            extensions = new PQTLSExtension[]{sig};
        }else{
            extensions = new PQTLSExtension[]{};
        }
        return extensions;
    }
}