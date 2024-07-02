package messages.extensions.implementations;

import crypto.enums.ECPointFormat;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ECPointFormatsExtensionTest {
    static ECPointFormatsExtension ecPointFormatsExtension1;
    static ECPointFormatsExtension ecPointFormatsExtension2;

    @BeforeAll
    public static void initialize() {
        ecPointFormatsExtension1 = new ECPointFormatsExtension(new ECPointFormat[]{
                ECPointFormat.ansiX962_compressed_char2,
                ECPointFormat.ansiX962_compressed_prime,
                ECPointFormat.uncompressed
        });
    }

    @Test
    public void testByteConversion(){
        ecPointFormatsExtension2 = (ECPointFormatsExtension) ECPointFormatsExtension.fromBytes(ecPointFormatsExtension1.getByteRepresentation());
        assertArrayEquals(ecPointFormatsExtension1.getByteRepresentation(), ecPointFormatsExtension2.getByteRepresentation());
    }
}