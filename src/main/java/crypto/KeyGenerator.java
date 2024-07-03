package crypto;


import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;

public class KeyGenerator {

    /*
    assumes that the CipherSuite is not TLS_NULL_ENCRYPTION
    */
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
}
