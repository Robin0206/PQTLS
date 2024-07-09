package crypto;


import crypto.enums.CurveIdentifier;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import misc.ByteUtils;

public class CryptographyModule {

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
        return (SecretKeyWithEncapsulation)generator.generateKey();
    }

    public static SecretKeyWithEncapsulation decapsulateSecret(PrivateKey privKeyClient, byte[] secret, String decapsAlgName, String keyAlgName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException{
        KeyGenerator generator = KeyGenerator.getInstance(decapsAlgName, "BCPQC");
        generator.init(new KEMExtractSpec(privKeyClient, secret, keyAlgName));
        return (SecretKeyWithEncapsulation)generator.generateKey();
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

    public static byte[] encryptAES(byte[] input, long iv, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding", "BC");
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
}
