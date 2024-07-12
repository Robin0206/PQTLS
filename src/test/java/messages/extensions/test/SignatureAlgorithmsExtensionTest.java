package messages.extensions.test;

import messages.extensions.PQTLSExtensionFactory;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static misc.Constants.*;
import static org.junit.jupiter.api.Assertions.*;

class SignatureAlgorithmsExtensionTest {
    static SignatureAlgorithmsExtension signatureAlgorithmsExtension1;
    static SignatureAlgorithmsExtension signatureAlgorithmsExtension2;
    @BeforeAll
    public static void initialize(){
        signatureAlgorithmsExtension1 = new SignatureAlgorithmsExtension(new byte[]{
                EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS,
                EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM
        });
    }
    @Test
    void testGenerationFromByteRepresentation(){
        signatureAlgorithmsExtension2 = (SignatureAlgorithmsExtension) PQTLSExtensionFactory.generateFromBytes(signatureAlgorithmsExtension1.getByteRepresentation());
        assertTrue(signatureAlgorithmsExtension1.equals(signatureAlgorithmsExtension2));
    }
}