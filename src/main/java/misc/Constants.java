package misc;

import crypto.enums.PQTLSCipherSuite;

public class Constants {

    public static final byte HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    public static final byte HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO = 0x02;
    public static final int  HELLO_MESSAGE_RANDOM_LENGTH = 32;


    public static final byte EXTENSION_IDENTIFIER_KEY_SHARE = 0x33;
    public static final byte EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS = 0x0d;
    public static final byte EXTENSION_IDENTIFIER_EC_POINT_FORMATS = 0x0b;
    public static final byte EXTENSION_IDENTIFIER_SUPPORTED_GROUPS = 0x0a;

    public static final int EXTENSION_KEY_SHARE_MIN_KEY_ARR_LENGTH = 1;
    public static final int EXTENSION_KEY_SHARE_KEY_LENGTH_FIELD_LENGTH = 2;
    public static final int EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET = 6;
    public static final byte EXTENSION_KEY_SHARE_CURVE_IDENTIFIER_NOT_SET = (byte) 0xff;
    public static final int EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS = 0x00;
    public static final int EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM = 0x01;
    public static final int EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET = 4;

    public static final byte HANDSHAKE_TYPE_FINISHED = 0x14;
    public static final byte HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 0x08;
    public static final byte ALERT_MESSAGE = 0x15;
    public static final PQTLSCipherSuite MANDATORY_CIPHERSUITE = PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_SPHINCS_WITH_CHACHA20_POLY1305_SHA256;
    public static final byte MESSAGE_TYPE_WRAPPED_RECORD = 0x17;
}
