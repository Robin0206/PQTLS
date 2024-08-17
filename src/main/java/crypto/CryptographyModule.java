package crypto;


import crypto.enums.CurveIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.spec.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.time.DateTimeException;
import java.util.Calendar;
import java.util.Date;

import misc.ByteUtils;
import org.bouncycastle.util.Arrays;
/**
 * @author Robin Kroker
 */
public class CryptographyModule {
    /**
     * @author Robin Kroker
     * Subclass responsible for hashing
     */
    public static class hashing {
        /**
         * Source: https://www.rfc-editor.org/rfc/rfc8446 section 7.1
         *
         * @param secret
         * @param label
         * @param messages
         * @param hashName
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] deriveSecret(byte[] secret, byte[] label, byte[] messages, String hashName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            return hkdfExpandLabel(
                    secret,
                    "hmac" + hashName,
                    label,
                    hash(messages, hashName),
                    MessageDigest.getInstance(hashName, "BC").getDigestLength()
            );
        }

        /**
         * Source: https://www.rfc-editor.org/rfc/rfc8446 section 7.1
         *
         * @param secret
         * @param label
         * @param messages
         * @param hashName
         * @param len
         * @return byte[]
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] deriveSecret(byte[] secret, byte[] label, byte[] messages, String hashName, int len) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            return hkdfExpandLabel(
                    secret,
                    "hmac" + hashName,
                    label,
                    hash(messages, hashName),
                    len
            );
        }

        /**
         * Source: Java Cryptography: Tools and Techniques by David Hook and John Eaves page 44
         *
         * @param input
         * @param hashName
         * @return byte[]
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         */
        public static byte[] hash(byte[] input, String hashName) throws NoSuchAlgorithmException, NoSuchProviderException {
            MessageDigest md = MessageDigest.getInstance(hashName, "BC");
            md.update(input);
            return md.digest();
        }

        /**
         * Source: https://www.rfc-editor.org/rfc/rfc5869 section 2.2
         *
         * @param salt
         * @param key
         * @param hMacName
         * @return byte[]
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] hkdfExtract(byte[] salt, byte[] key, String hMacName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            SecretKey macKey = new SecretKeySpec(key, hMacName);
            Mac hMac = Mac.getInstance(hMacName, "BC");
            hMac.init(macKey);
            hMac.update(salt);
            return hMac.doFinal();
        }

        /**
         * Source: https://www.rfc-editor.org/rfc/rfc5869 section 2.2
         *
         * @param key
         * @param hMacName
         * @return byte[]
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] hkdfExtract(byte[] key, String hMacName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            SecretKey macKey = new SecretKeySpec(key, hMacName);
            Mac hMac = Mac.getInstance(hMacName, "BC");
            hMac.init(macKey);
            byte[] salt = new byte[hMac.getMacLength()];
            hMac.update(salt);
            return hMac.doFinal();
        }

        /**
         * Source: https://www.rfc-editor.org/rfc/rfc5869 section 2.3
         *
         * @param key
         * @param hMacName
         * @param info
         * @param L
         * @return byte[]
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] hkdfExpand(byte[] key, String hMacName, byte[] info, int L) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            SecretKey macKey = new SecretKeySpec(key, hMacName);
            Mac hMac = Mac.getInstance(hMacName, "BC");
            hMac.init(macKey);
            int N = L;
            byte[][] T = new byte[N][];
            T[0] = new byte[0];
            for (int i = 1; i < T.length; i++) {
                hMac.init(macKey);
                hMac.update(Arrays.concatenate(new byte[][]{
                        T[i - 1],
                        info,
                        new byte[]{(byte) i}
                }));
                T[i] = hMac.doFinal();
            }
            byte[] flattenedT = ByteUtils.flatten(T);
            byte[] result = new byte[L];
            System.arraycopy(flattenedT, 0, result, 0, L);
            return result;
        }

        /**
         * Source: https://www.rfc-editor.org/rfc/rfc5869 section 2.3
         *
         * @param key
         * @param hMacName
         * @param label
         * @param context
         * @param L
         * @return byte[]
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] hkdfExpandLabel(byte[] key, String hMacName, byte[] label, byte[] context, int L) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            return hkdfExpand(key, hMacName, Arrays.concatenate(new byte[][]{label, context}), L);
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 46 to 47
         *
         * @param hMacName
         * @param input
         * @param key
         * @return byte[]
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] hMac(String hMacName, byte[] input, byte[] key) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            Mac hMac = Mac.getInstance(hMacName, "BC");
            hMac.init(new SecretKeySpec(key, hMacName));
            hMac.update(input);
            return hMac.doFinal();
        }
    }


    /**
     * @author Robin Kroker
     * Subclass responsible for creating, converting and en/decapsulating keys
     */
    public static class keys {
        /**
         * @param identifiers
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static KeyPair[] generateECKeyPairs(CurveIdentifier[] identifiers) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPair[] result = new KeyPair[identifiers.length];
            for (int i = 0; i < identifiers.length; i++) {
                result[i] = generateECKeyPair(identifiers[i]);
            }
            return result;
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 182 to 183 (adapted for Elliptic curves)
         *
         * @param identifier
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static KeyPair generateECKeyPair(CurveIdentifier identifier) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(identifier.toString());
            generator.initialize(ecGenParameterSpec);
            return generator.generateKeyPair();
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 197
         *
         * @param privateKey
         * @param publicKey
         * @param algName
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         */
        public static byte[] generateECSharedSecret(PrivateKey privateKey, PublicKey publicKey, String algName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH", "BC");
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            return agreement.generateSecret(algName).getEncoded();
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 473
         *
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static KeyPair generateKyberKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Kyber", "BCPQC");
            generator.initialize(KyberParameterSpec.kyber768);
            return generator.generateKeyPair();
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 470
         *
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static KeyPair generateFrodoKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Frodo", "BCPQC");
            generator.initialize(FrodoParameterSpec.frodokem640shake);
            return generator.generateKeyPair();
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 473
         *
         * @param clientPublicKey
         * @param encapsAlgName
         * @param keyAlgName
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static SecretKeyWithEncapsulation generateEncapsulatedSecret(PublicKey clientPublicKey, String encapsAlgName, String keyAlgName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyGenerator generator = KeyGenerator.getInstance(encapsAlgName, "BCPQC");
            generator.init(new KEMGenerateSpec(clientPublicKey, keyAlgName), new SecureRandom());
            return (SecretKeyWithEncapsulation) generator.generateKey();
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 473
         *
         * @param privKeyClient
         * @param secret
         * @param decapsAlgName
         * @param keyAlgName
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static SecretKeyWithEncapsulation decapsulateSecret(PrivateKey privKeyClient, byte[] secret, String decapsAlgName, String keyAlgName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyGenerator generator = KeyGenerator.getInstance(decapsAlgName, "BCPQC");
            generator.init(new KEMExtractSpec(privKeyClient, secret, keyAlgName));
            return (SecretKeyWithEncapsulation) generator.generateKey();
        }

        /**
         * @param input
         * @param algName
         * @param provider
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeySpecException
         */
        public static PublicKey byteArrToPublicKey(byte[] input, String algName, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            return KeyFactory.getInstance(algName, provider)
                    .generatePublic(
                            new X509EncodedKeySpec(
                                    input
                            )
                    )
                    ;
        }

        /**
         * @param key
         * @param algName
         * @return
         */
        public static Key byteArrToSymmetricKey(byte[] key, String algName) {
            return new SecretKeySpec(key, algName);
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 463
         *
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static KeyPair generateSPHINCSKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
            keyPairGenerator.initialize(SPHINCSPlusParameterSpec.shake_256f, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 463 (Adapted for Dilithium)
         *
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         */
        public static KeyPair generateDilithiumKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
            keyPairGenerator.initialize(DilithiumParameterSpec.dilithium5, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
    }

    /**
     * @author Robin Kroker
     * Subclass responsible for symmetric ciphers
     * All Methods in this Subclass are Adaptations from the code on page 35 and 36 of the book: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves
     */
    public static class symmetric {

        /**
         * @param input
         * @param iv
         * @param key
         * @return
         * @throws NoSuchPaddingException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         * @throws InvalidKeyException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         */
        public static byte[] encryptAES(byte[] input, byte[] iv, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(input);
        }

        /**
         * @param input
         * @param nonce
         * @param key
         * @return
         * @throws NoSuchPaddingException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         * @throws InvalidKeyException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         */
        public static byte[] encryptChaCha(byte[] input, byte[] nonce, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
            return cipher.doFinal(input);
        }

        /**
         * @param input
         * @param iv
         * @param key
         * @return
         * @throws NoSuchPaddingException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         * @throws InvalidKeyException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         */
        public static byte[] decryptAES(byte[] input, byte[] iv, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(input);
        }

        /**
         * @param input
         * @param nonce
         * @param key
         * @return
         * @throws NoSuchPaddingException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidAlgorithmParameterException
         * @throws InvalidKeyException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         */
        public static byte[] decryptChaCha(byte[] input, byte[] nonce, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
            return cipher.doFinal(input);
        }
    }

    /**
     * @author Robin Kroker
     * Subclass responsible for certificates and signatures
     */
    public static class certificate {
        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 452 (Adapted for Sphincs and Dilithium)
         *
         * @param algName
         * @return
         * @throws InvalidAlgorithmParameterException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws OperatorCreationException
         */
        public static X509CertificateHolder generateSelfSignedTestCertificate(String algName) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
            X500Name name = new X500Name("CN=TestCertificate");
            KeyPair keyPair = algName == "SPHINCSPlus" ? keys.generateSPHINCSKeyPair() : keys.generateDilithiumKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, -1);
            Date start = cal.getTime();
            cal.add(Calendar.YEAR, 2);
            Date end = cal.getTime();

            X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                    name,
                    BigInteger.valueOf(0),
                    start,
                    end,
                    name,
                    keyPair.getPublic()
            );

            ContentSigner signer = new JcaContentSignerBuilder(algName)
                    .setProvider("BCPQC")
                    .build(privateKey);
            return certBldr.build(signer);
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 452 (Adapted for Sphincs and Dilithium)
         *
         * @param keyPair
         * @param algName
         * @return
         * @throws OperatorCreationException
         */
        public static X509CertificateHolder generateSelfSignedTestCertificate(KeyPair keyPair, String algName) throws OperatorCreationException {
            X500Name name = new X500Name("CN=TestCertificate");
            PrivateKey privateKey = keyPair.getPrivate();
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, -1);
            Date start = cal.getTime();
            cal.add(Calendar.YEAR, 2);
            Date end = cal.getTime();
            X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                    name,
                    BigInteger.valueOf(0),
                    start,
                    end,
                    name,
                    keyPair.getPublic()
            );

            ContentSigner signer = new JcaContentSignerBuilder(algName)
                    .setProvider("BCPQC")
                    .build(privateKey);
            return certBldr.build(signer);
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 215
         *
         * @param input
         * @return
         * @throws CertificateException
         */
        public static X509Certificate holderToCertificate(X509CertificateHolder input) throws CertificateException {
            return new JcaX509CertificateConverter().getCertificate(input);
        }

        /**
         * only does verify that the signatures are correct! This is done manually because of flexibility of using a normal array as an argument
         *
         * @param certificates
         * @return
         * @throws CertificateException
         * @throws NoSuchProviderException
         * @throws NoSuchAlgorithmException
         * @throws SignatureException
         * @throws InvalidKeySpecException
         * @throws InvalidKeyException
         */
        public static boolean verifyCertificateChain(X509CertificateHolder[] certificates) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException {
            for (int index = 0; index < certificates.length - 1; index++) {
                X509Certificate messageCert = holderToCertificate(certificates[index]);
                X509Certificate signersCert = holderToCertificate(certificates[index + 1]);
                byte[] messageSignature = messageCert.getSignature();
                byte[] messageCertBytes = messageCert.getEncoded();
                PublicKey signersPublicKey = signersCert.getPublicKey();
                String signersSigAlgName = signersCert.getSigAlgName();
                if (!verifySignature(signersPublicKey, signersSigAlgName, messageCertBytes, messageSignature)) {
                    return false;
                }
                if(CryptographyModule.certificate.verifyDate(messageCert)){

                }
            }
            return true;
        }

        /**
         * Checks if a certificates NotBefore and NotAfter fields are still valid
         * @param messageCert
         * @return
         */
        public static boolean verifyDate(X509Certificate messageCert) {
            Date now = new Date();
            return messageCert.getNotBefore().before(now) && messageCert.getNotAfter().after(now);
        }

        /**
         * Source: "Java Cryptography: Tools and Techniques" by David Hook and john Eaves page 127 (Adapted for Sphincs and Dilithium)
         *
         * @param publicKey
         * @param algName
         * @param originalMessage
         * @param signature
         * @return
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException
         * @throws SignatureException
         * @throws InvalidKeySpecException
         */
        public static boolean verifySignature(PublicKey publicKey, String algName, byte[] originalMessage, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidKeySpecException {
            Signature sigAlg = Signature.getInstance(algName, "BCPQC");
            sigAlg.initVerify(
                    //For some strange reason, this is the only way to verify sphincs signatures
                    //it will throw an exception if you don't convert it to bytes and back
                    keys.byteArrToPublicKey(publicKey.getEncoded(), algName, "BCPQC")
            );
            sigAlg.update(originalMessage);
            return sigAlg.verify(signature);
        }
    }
}
