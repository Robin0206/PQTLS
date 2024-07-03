package messages.extensions.test;

import messages.extensions.PQTLSExtension;
import messages.extensions.PQTLSExtensionFactory;
import messages.extensions.implementations.KeyShareExtension;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class KeyShareExtensionTest {
    static KeyShareExtension keyShareExtension1;
    static KeyShareExtension keyShareExtension2;

    @BeforeAll
    static void initialize() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("curve25519");
        kpg.initialize(ecGenParameterSpec);
        ECPublicKey key = (ECPublicKey) kpg.generateKeyPair().getPublic();
        byte[]frodoKey = new byte[168];
        new SecureRandom().nextBytes(frodoKey);
        byte[] ecKey = key.getEncoded();
        byte[] sessionID = new byte[32];
        keyShareExtension1 = new KeyShareExtension(
                new byte[][]{ecKey, frodoKey}
        );
    }

    @Test
    void testGenerationFromByteRepresentation(){
        keyShareExtension2 = (KeyShareExtension) PQTLSExtensionFactory.generateFromBytes(keyShareExtension1.getByteRepresentation());
        assertTrue(keyShareExtension1.equals(keyShareExtension2));
    }
    @Test
    void testRandomGenerationFromBytes(){
        assertAll(()->{
            SecureRandom rand = new SecureRandom();
            for(int i = 0; i < 1000; i++){
                byte[][] keys = generateRandomKeys(rand);
                keyShareExtension1 = new KeyShareExtension(keys);
                keyShareExtension2 = (KeyShareExtension) PQTLSExtensionFactory.generateFromBytes(keyShareExtension1.getByteRepresentation());
                assertTrue(keyShareExtension1.equals(keyShareExtension2));
            }
        });
    }

    private static byte[][] generateRandomKeys(SecureRandom rand) {
        int numberOfKeys = 1 + Math.abs(rand.nextInt())%10;
        byte[][]keys = new byte[numberOfKeys][];
        for (int j = 0; j < keys.length; j++) {
            keys[j] = new byte[Math.abs(rand.nextInt())%10000];
            rand.nextBytes(keys[j]);
        }
        return keys;
    }
}