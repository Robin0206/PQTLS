package crypto;


import crypto.enums.CurveIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.Dilithium;
import org.bouncycastle.pqc.jcajce.spec.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import misc.ByteUtils;
import org.bouncycastle.util.Arrays;

public class CryptographyModule {
    public static class hashing {
        public static byte[] deriveSecret(byte[] secret, byte[] label, byte[] messages, String hashName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            return hkdfExpandLabel(
                    secret,
                    "hmac"+hashName,
                    label,
                    hash(messages, hashName),
                    MessageDigest.getInstance(hashName, "BC").getDigestLength()
            );
        }
        public static byte[] deriveSecret(byte[] secret, byte[] label, byte[] messages, String hashName, int len) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            return hkdfExpandLabel(
                    secret,
                    "hmac"+hashName,
                    label,
                    hash(messages, hashName),
                    len
            );
        }
        public static byte[] hash(byte[] input, String hashName) throws NoSuchAlgorithmException, NoSuchProviderException {
            MessageDigest md = MessageDigest.getInstance(hashName, "BC");
            md.update(input);
            return md.digest();
        }
        // https://www.rfc-editor.org/rfc/rfc5869 section 2.2
        public static byte[] hkdfExtract(byte[] salt, byte[] key, String hMacName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            SecretKey macKey = new SecretKeySpec(key, hMacName);
            Mac hMac = Mac.getInstance(hMacName, "BC");
            hMac.init(macKey);
            hMac.update(salt);
            return hMac.doFinal();
        }

        // https://www.rfc-editor.org/rfc/rfc5869 section 2.2
        public static byte[] hkdfExtract(byte[] key, String hMacName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            SecretKey macKey = new SecretKeySpec(key, hMacName);
            Mac hMac = Mac.getInstance(hMacName, "BC");
            hMac.init(macKey);
            byte[] salt = new byte[hMac.getMacLength()];
            hMac.update(salt);
            return hMac.doFinal();
        }

        // https://www.rfc-editor.org/rfc/rfc5869 section 2.3
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
        // https://www.rfc-editor.org/rfc/rfc5869 section 2.3
        public static byte[] hkdfExpandLabel(byte[] key, String hMacName, byte[] label, byte[] context, int L) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
            return hkdfExpand(key, hMacName, Arrays.concatenate(new byte[][]{label,context}), L);
        }
    }


    /*
    Subclass responsible for creating, converting and en/decapsulating keys
     */
    public static class keys {
        public static KeyPair[] generateECKeyPairs(CurveIdentifier[] identifiers) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPair[] result = new KeyPair[identifiers.length];
            for (int i = 0; i < identifiers.length; i++) {
                result[i] = generateECKeyPair(identifiers[i]);
            }
            return result;
        }

        public static KeyPair generateECKeyPair(CurveIdentifier identifier) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(identifier.toString());
            generator.initialize(ecGenParameterSpec);
            return generator.generateKeyPair();
        }

        public static byte[] generateECSharedSecret(PrivateKey privateKey, PublicKey publicKey, String algName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH", "BC");
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            return agreement.generateSecret(algName).getEncoded();
        }

        public static KeyPair generateKyberKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Kyber", "BCPQC");
            generator.initialize(KyberParameterSpec.kyber768);
            return generator.generateKeyPair();
        }

        public static KeyPair generateFrodoKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Frodo", "BCPQC");
            generator.initialize(FrodoParameterSpec.frodokem640shake);
            return generator.generateKeyPair();
        }

        public static SecretKeyWithEncapsulation generateEncapsulatedSecret(PublicKey clientPublicKey, String encapsAlgName, String keyAlgName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyGenerator generator = KeyGenerator.getInstance(encapsAlgName, "BCPQC");
            generator.init(new KEMGenerateSpec(clientPublicKey, keyAlgName), new SecureRandom());
            return (SecretKeyWithEncapsulation) generator.generateKey();
        }

        public static SecretKeyWithEncapsulation decapsulateSecret(PrivateKey privKeyClient, byte[] secret, String decapsAlgName, String keyAlgName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyGenerator generator = KeyGenerator.getInstance(decapsAlgName, "BCPQC");
            generator.init(new KEMExtractSpec(privKeyClient, secret, keyAlgName));
            return (SecretKeyWithEncapsulation) generator.generateKey();
        }

        public static PublicKey byteArrToPublicKey(byte[] input, String algName, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            return KeyFactory.getInstance(algName, provider)
                    .generatePublic(
                            new X509EncodedKeySpec(
                                    input
                            )
                    )
                    ;
        }

        public static Key byteArrToSymmetricKey(byte[] key, String algName) {
            return new SecretKeySpec(key, algName);
        }
    }

    /*
    Subclass responsible for symmetric ciphers
     */
    public static class symmetric {
        public static byte[] encryptAES(byte[] input, long iv, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ByteUtils.longToByteArray(iv)));
            return cipher.doFinal(input);
        }

        public static byte[] encryptChaCha(byte[] input, long nonce, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("ChaCha20Poly1305", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ByteUtils.longToByteArray(nonce)));
            return cipher.doFinal(input);
        }

        public static byte[] decryptAES(byte[] input, long iv, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ByteUtils.longToByteArray(iv)));
            return cipher.doFinal(input);
        }

        public static byte[] decryptChaCha(byte[] input, long nonce, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("ChaCha20Poly1305", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ByteUtils.longToByteArray(nonce)));
            return cipher.doFinal(input);
        }

        //______________________________________________________

        public static byte[] encryptAES(byte[] input, byte[] iv, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(input);
        }

        public static byte[] encryptChaCha(byte[] input, byte[] nonce, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("ChaCha20Poly1305", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
            return cipher.doFinal(input);
        }

        public static byte[] decryptAES(byte[] input, byte[] iv, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(input);
        }

        public static byte[] decryptChaCha(byte[] input, byte[] nonce, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("ChaCha20Poly1305", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
            return cipher.doFinal(input);
        }
    }

    public class certificate{
        public static X509CertificateHolder generateSelfSignedTestCertificate(String algName) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
            X500Name name = new X500Name("CN=TestCertificate");
            KeyPair keyPair = generateSigAlgKeyPair(algName);
            PrivateKey privateKey = keyPair.getPrivate();
            X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                    name,
                    BigInteger.valueOf(0),
                    new Date(),
                    new Date(),
                    name,
                    keyPair.getPublic()
            );

            ContentSigner signer = new JcaContentSignerBuilder(algName)
                    .setProvider("BCPQC")
                    .build(privateKey);
            return certBldr.build(signer);
        }
    }

    private static KeyPair generateSigAlgKeyPair(String algName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, "BCPQC");
        switch (algName){
            case "SPHINCSPlus":
                kpg.initialize(SPHINCSPlusParameterSpec.sha2_128f);
                break;
            case "Dilithium":
                kpg.initialize(DilithiumParameterSpec.dilithium5);
                break;
        }
        return kpg.generateKeyPair();
    }
}
