package messages.implementations;

import crypto.CryptographyModule;
import crypto.enums.CurveIdentifier;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import misc.Constants;
import org.junit.jupiter.api.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class EncryptedExtensionsTest {
    EncryptedExtensions encryptedExtensions1;
    EncryptedExtensions encryptedExtensions2;

    @Test
    void testGenerationFromBytesAndEqualsFromBytes() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair ecKeyPair = CryptographyModule.generateECKeyPair(CurveIdentifier.secp256r1);
        KeyPair frodoKeyPair = CryptographyModule.generateFrodoKeyPair();
        KeyPair kyberKeyPair = CryptographyModule.generateKyberKeyPair();
        KeyShareExtension keyShareExtension = new KeyShareExtension(
                new byte[][]{
                        ecKeyPair.getPublic().getEncoded(),
                        frodoKeyPair.getPublic().getEncoded(),
                        kyberKeyPair.getPublic().getEncoded()
                }
        );
        SignatureAlgorithmsExtension signatureAlgorithmsExtension = new SignatureAlgorithmsExtension(
                new byte[]{
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS,
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_FALCON,
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM
                }
        );
        encryptedExtensions1 = new EncryptedExtensions(
                new PQTLSExtension[]{
                        keyShareExtension,
                        signatureAlgorithmsExtension
                }
        );
        encryptedExtensions2 = new EncryptedExtensions(encryptedExtensions1.getBytes());
        assertTrue(encryptedExtensions1.equals(encryptedExtensions2));
    }
    @Test
    void testGenerationFromBytesMessageBytes() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair ecKeyPair = CryptographyModule.generateECKeyPair(CurveIdentifier.secp256r1);
        KeyPair frodoKeyPair = CryptographyModule.generateFrodoKeyPair();
        KeyPair kyberKeyPair = CryptographyModule.generateKyberKeyPair();
        KeyShareExtension keyShareExtension = new KeyShareExtension(
                new byte[][]{
                        ecKeyPair.getPublic().getEncoded(),
                        frodoKeyPair.getPublic().getEncoded(),
                        kyberKeyPair.getPublic().getEncoded()
                }
        );
        SignatureAlgorithmsExtension signatureAlgorithmsExtension = new SignatureAlgorithmsExtension(
                new byte[]{
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS,
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_FALCON,
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM
                }
        );
        encryptedExtensions1 = new EncryptedExtensions(
                new PQTLSExtension[]{
                        keyShareExtension,
                        signatureAlgorithmsExtension
                }
        );
        encryptedExtensions2 = new EncryptedExtensions(encryptedExtensions1.getBytes());
        assertArrayEquals(encryptedExtensions1.getBytes(), encryptedExtensions2.getBytes());
    }
}