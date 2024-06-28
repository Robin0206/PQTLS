package messages.extensions.test;

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
                new byte[][]{ecKey, frodoKey},
                new byte[]{0x00, 0x1d}
        );
    }

    @Test
    void testGenerationFromByteRepresentation(){
        keyShareExtension2 = (KeyShareExtension) PQTLSExtensionFactory.generateFromBytes(keyShareExtension1.getByteRepresentation());
        assertTrue(keyShareExtension1.equals(keyShareExtension2));
    }
}