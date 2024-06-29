package misc;

public class Constants {

    public static final byte HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    public static final byte HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO = 0x02;

    public static final int EC_PARAMETER_LENGTH = 2;
    public static final byte[] CURVE_25519_IDENTIFIER = {0x00, 0x1d};


    public static final byte EXTENSION_IDENTIFIER_KEY_SHARE = 0x33;
    public static final byte EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS = 0x0d;

    public static final int EXTENSION_KEY_SHARE_MAX_KEY_ARR_LENGTH = 3;
    public static final int EXTENSION_KEY_SHARE_KEY_LENGTH_FIELD_LENGTH = 2;
    public static final int EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET = 7;

    public static final int EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS = 0x00;
    public static final int EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM = 0x01;
    public static final int EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_FALCON = 0x02;
    public static final int EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET = 4;
}
