package crypto;


import crypto.enums.CurveIdentifier;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.KeyGenerator;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

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

    public static KeyPair generateKyberKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        generator.initialize(KyberParameterSpec.kyber768);
        return generator.generateKeyPair();
    }

    public static KeyPair generateFrodoKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Frodo", "BCPQC");
        generator.initialize(FrodoParameterSpec.frodokem976shake);
        return generator.generateKeyPair();
    }

    public static SecretKeyWithEncapsulation generateEncapsulatedSecret(PublicKey clientPublicKey, String algName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator generator = KeyGenerator.getInstance(algName, "BCPQC");
        generator.init(new KEMGenerateSpec(clientPublicKey, "AES"), new SecureRandom());
        return (SecretKeyWithEncapsulation)generator.generateKey();
    }

    public static SecretKeyWithEncapsulation generateClient(PrivateKey privKeyClient, byte[] secret, String algName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException{
        KeyGenerator generator = KeyGenerator.getInstance("Kyber", "BCPQC");
        generator.init(new KEMExtractSpec(privKeyClient, secret, "AES"));
        return (SecretKeyWithEncapsulation)generator.generateKey();
    }
}
