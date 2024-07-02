package messages.extensions;

import messages.extensions.implementations.ECPointFormatsExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import messages.extensions.implementations.SupportedGroupsExtension;

import static misc.Constants.*;

public class PQTLSExtensionFactory {
    public static PQTLSExtension generateFromBytes(byte[] input){
        return switch (input[1]) {// only the second byte gets used because the first is always 0x00
            case EXTENSION_IDENTIFIER_KEY_SHARE -> KeyShareExtension.fromBytes(input);
            case EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS -> SignatureAlgorithmsExtension.fromBytes(input);
            case EXTENSION_IDENTIFIER_EC_POINT_FORMATS -> ECPointFormatsExtension.fromBytes(input);
            case EXTENSION_IDENTIFIER_SUPPORTED_GROUPS -> SupportedGroupsExtension.fromBytes(input);
            default -> throw new IllegalArgumentException("Invalid Identifier");
        };
    }
}
