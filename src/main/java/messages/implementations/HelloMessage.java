package messages.implementations;

import crypto.enums.CipherSuite;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtensionFactory;
import messages.extensions.PQTLSExtension;
import misc.ByteUtils;
import org.bouncycastle.util.Arrays;

import java.util.ArrayList;

import static misc.Constants.*;

//Builder Pattern
public class HelloMessage implements PQTLSMessage {

    //Constructor gets only used in the builder
    private HelloMessage(HelloBuilder builder) {
        this.handShakeMessageType = builder.handShakeMessageType;
        this.legacyVersion = builder.legacyVersion;
        this.lengthAfterRecordHeader = builder.lengthAfterRecordHeader;
        this.lengthAfterHandshakeHeader = builder.lengthAfterHandshakeHeader;
        this.random = builder.random;
        this.sessionIDLength = builder.sessionIDLength;
        this.sessionID = builder.sessionID;
        this.cipherSuitesLength = builder.cipherSuitesLength;
        this.cipherSuites = builder.cipherSuites;
        this.extensionsLength = builder.extensionsLength;
        this.extensions = builder.extensions;
        this.extensionBytes = builder.extensionBytes;
        this.messageBytes = builder.messageBytes;
    }

    //Used for testing
    public boolean equals(HelloMessage message) {
        return (java.util.Arrays.equals(this.legacyVersion, message.legacyVersion) &&
                this.lengthAfterRecordHeader == message.lengthAfterRecordHeader &&
                this.handShakeMessageType == message.handShakeMessageType &&
                this.lengthAfterHandshakeHeader == message.lengthAfterHandshakeHeader &&
                java.util.Arrays.equals(this.random, message.random) &&
                this.sessionIDLength == message.sessionIDLength &&
                java.util.Arrays.equals(this.sessionID,message.sessionID)&&
                this.cipherSuitesLength == message.cipherSuitesLength &&
                java.util.Arrays.equals(this.cipherSuites, message.cipherSuites) &&
                this.extensionsLength == message.extensionsLength &&
                java.util.Arrays.equals(this.extensionBytes, message.extensionBytes) &&
                java.util.Arrays.equals(this.messageBytes, message.messageBytes)
        );
    }

    //record header
    private final byte recordType = 0x16;
    private final short lengthAfterRecordHeader;

    //handshake header
    private int handShakeMessageType = 0x01;
    private final int lengthAfterHandshakeHeader;

    //client version
    private byte[] legacyVersion = {0x03, 0x03}; // https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2 [S. 29, Z. 1-8]

    //client random
    private final byte[] random;// 32 bytes

    //sessionID
    private final byte sessionIDLength;
    private final byte[] sessionID;

    //cipher suites
    private final byte cipherSuitesLength;
    private final CipherSuite[] cipherSuites;

    //compression methods
    private final byte compressionMethodsLength = 0x1;
    private final byte compressionMethods = 0x00; //default null compression

    //extensions
    private final short extensionsLength;
    private final PQTLSExtension[] extensions;
    private final byte[] extensionBytes;

    private final byte[] messageBytes;

    @Override
    public void printVerbose() {
        if (this.handShakeMessageType == HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO) {
            System.out.println("====================================Client Hello====================================");
        } else {
            System.out.println("====================================Server Hello====================================");
        }
        System.out.println("RecordType:      " + recordType);
        System.out.println("LegacyVersion: " + java.util.Arrays.toString(legacyVersion));
        System.out.println("LengthAfterRecordHeader: " + lengthAfterRecordHeader);
        System.out.println("HandShakeMessageType: " + handShakeMessageType);
        System.out.println("lengthAfterHandshakeHeader: " + lengthAfterHandshakeHeader);
        System.out.println("LegacyVersion: " + java.util.Arrays.toString(legacyVersion));
        System.out.println("Client Random: " + java.util.Arrays.toString(random));
        System.out.println("SessionIDLength: " + sessionIDLength);
        System.out.println("SessionID: " + java.util.Arrays.toString(sessionID));
        System.out.println("CipherSuiteLength: " + cipherSuitesLength);
        System.out.println();
        System.out.println("_____________CipherSuites_____________");
        for (int i = 0; i < cipherSuitesLength; i++) {
            System.out.println("\t" + cipherSuites[i].name());
        }
        System.out.println();
        System.out.println("CompressionMethodsLength: " + compressionMethodsLength);
        System.out.println("CompressionMethods: " + compressionMethods);
        System.out.println("ExtensionsLength: " + extensionsLength);
        System.out.println();
        System.out.println("______________Extensions______________");
        for (PQTLSExtension extension : extensions) {
            extension.printVerbose();
        }
        System.out.println();
        System.out.println("______________Raw Bytes______________");
        System.out.println(java.util.Arrays.toString(messageBytes));
    }

    @Override
    public byte[] getBytes() {
        return messageBytes;
    }

    public byte[] getRandom() {
        return random;
    }

    public int getExtensionsLength() {
        return extensionsLength;
    }

    public CipherSuite[] getCipherSuites() {
        return cipherSuites;
    }

    public byte[] getSessionID() {
        return sessionID;
    }

    public PQTLSExtension[] getExtensions() {
        return extensions;
    }

    public static class HelloBuilder {
        //record header
        private byte[] legacyVersion;
        private short lengthAfterRecordHeader;

        //handshake header
        private int handShakeMessageType;
        private int lengthAfterHandshakeHeader;

        //client random
        private byte[] random;// 32 bytes

        //sessionID
        private byte sessionIDLength;
        private byte[] sessionID;

        //cipher suites
        private byte cipherSuitesLength;
        private CipherSuite[] cipherSuites;
        private byte[] cipherSuiteBytes;

        //extensions
        private short extensionsLength;
        private PQTLSExtension[] extensions;
        private byte[] extensionBytes;

        private byte[] messageBytes;
        private boolean legacyVersionSet = false;
        private boolean sessionIDSet = false;
        private boolean cipherSuitesSet = false;
        private boolean extensionsSet = false;
        private boolean randomSet = false;
        private boolean messageTypeSet = false;

        //===================================Methods for setting variables===================================
        public HelloBuilder handShakeType(byte handShakeType) {
            if (
                    (handShakeType != HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO &&
                            handShakeType != HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO) ||
                            (cipherSuitesSet &&
                                    handShakeType == HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO &&
                                    cipherSuites.length != 1)
            ) {
                throw new IllegalArgumentException("Invalid handshakeType because of either wrong argument or \n" +
                        "using serverHello and cipherSuites length is bigger than 1");
            }
            this.handShakeMessageType = handShakeType;
            this.messageTypeSet = true;
            return this;
        }

        public HelloBuilder random(byte[] random) {
            if (random.length != HELLO_MESSAGE_RANDOM_LENGTH) {
                throw new IllegalArgumentException("Random byte Array should have a length of 32");
            }
            this.random = random;
            this.randomSet = true;
            return this;
        }

        public HelloBuilder LegacyVersion(byte[] legacyVersion) {
            this.legacyVersion = legacyVersion;
            this.legacyVersionSet = true;
            return this;
        }

        public HelloBuilder sessionID(byte[] sessionID) {
            this.sessionID = sessionID;
            this.sessionIDLength = (byte) sessionID.length;
            this.sessionIDSet = true;
            return this;
        }

        public HelloBuilder cipherSuites(CipherSuite[] cipherSuites) {
            if (cipherSuites.length == 0) {
                throw new IllegalArgumentException("There must be at least one cipher-suite");
            }
            if (
                    messageTypeSet &&
                            handShakeMessageType == HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO &&
                            cipherSuites.length != 1
            ) {
                throw new IllegalArgumentException("A server-hello-message should have only one cipherSuite");
            }
            this.cipherSuitesLength = (byte) cipherSuites.length;
            this.cipherSuites = cipherSuites;
            this.cipherSuiteBytes = new byte[cipherSuitesLength];
            for (int i = 0; i < cipherSuitesLength; i++) {
                cipherSuiteBytes[i] = (byte) cipherSuites[i].ordinal();
            }
            cipherSuitesSet = true;
            return this;
        }

        public HelloBuilder extensions(PQTLSExtension[] extensions) {
            this.extensions = extensions;
            ArrayList<byte[]> arrBuffer = new ArrayList<>();
            for (PQTLSExtension extension : extensions) {
                arrBuffer.add(extension.getByteRepresentation());
            }
            ArrayList<Byte> resultBuffer = new ArrayList<>();
            for (byte[] extensionBytes : arrBuffer) {
                for (byte b : extensionBytes) {
                    resultBuffer.add(b);
                }
            }
            extensionBytes = new byte[resultBuffer.size()];
            for (int i = 0; i < resultBuffer.size(); i++) {
                extensionBytes[i] = resultBuffer.get(i);
            }
            extensionsLength = (short) extensionBytes.length;
            extensionsSet = true;
            return this;
        }

        /*
        Sets all variables from the raw message bytes.
        Cant be called with any other builder-method except build().
         */
        public HelloBuilder fromBytes(byte[] messageBytes) {
            if (
                    extensionsSet ||
                            cipherSuitesSet ||
                            sessionIDSet ||
                            legacyVersionSet ||
                            messageTypeSet ||
                            randomSet
            ) {
                throw new IllegalArgumentException("From bytes cannot be used with any other builder-method except build()");
            }
            legacyVersion = new byte[]{messageBytes[1], messageBytes[2]};
            lengthAfterRecordHeader = (short) ((messageBytes[4] << 8) + messageBytes[5]);
            handShakeMessageType = messageBytes[5];
            lengthAfterHandshakeHeader = (int) messageBytes[6] << 16 + messageBytes[6] << 8 + messageBytes[7];
            random = new byte[32];
            System.arraycopy(
                    messageBytes,
                    11,
                    random,
                    0,
                    random.length
            );
            randomSet = true;
            sessionIDLength = messageBytes[11 + random.length];
            sessionID = new byte[sessionIDLength];
            System.arraycopy(
                    messageBytes,
                    12 + random.length,
                    sessionID,
                    0,
                    sessionIDLength);
            cipherSuitesLength = messageBytes[12 + random.length + sessionID.length];
            cipherSuiteBytes = new byte[cipherSuitesLength];
            System.arraycopy(
                    messageBytes,
                    13 + random.length + sessionID.length, cipherSuiteBytes,
                    0,
                    cipherSuitesLength
            );
            fillCipherSuitesFromBytes();
            extensionsLength = ByteUtils.byteArrToShort(new byte[]{
                    messageBytes[15 + random.length + sessionIDLength + cipherSuitesLength],
                    messageBytes[16 + random.length + sessionIDLength + cipherSuitesLength]
            });
            extensionBytes = new byte[extensionsLength];
            System.arraycopy(
                    messageBytes,
                    17 + random.length + sessionIDLength + cipherSuitesLength,
                    extensionBytes,
                    0,
                    extensionsLength
            );
            extensions = PQTLSExtensionFactory.generateMultipleFromBytes(extensionBytes);
            this.messageBytes = messageBytes.clone();
            legacyVersionSet = true;
            cipherSuitesSet = true;
            sessionIDSet = true;
            extensionsSet = true;
            randomSet = true;
            messageTypeSet = true;
            return this;
        }

        //========================================Final build method=========================================

        public HelloMessage build() {
            if (
                    !extensionsSet ||
                            !cipherSuitesSet ||
                            !sessionIDSet ||
                            !legacyVersionSet ||
                            !messageTypeSet ||
                            !randomSet
            ) {
                throw new IllegalArgumentException("Not all necessary builder-methods are called before build.");
            }
            //fill messageBytes
            this.messageBytes = Arrays.concatenate(new byte[][]{
                    {0x16, this.legacyVersion[0], this.legacyVersion[1]},// record header
                    {0x00, 0x00}, // number of following bytes
                    {(byte) this.handShakeMessageType},
                    {0x00, 0x00, 0x00},// number of following bytes
                    {0x03, 0x03},// client version
                    random,
                    {sessionIDLength},
                    sessionID,
                    {cipherSuitesLength},
                    cipherSuiteBytes,
                    {0x01, 0x00}, // compression methods
                    ByteUtils.shortToByteArr(extensionsLength), // extensions length
                    extensionBytes
            });
            //calculate lengths of bytes after record header and bytes after handshake header
            lengthAfterRecordHeader = (short) (messageBytes.length - 5);
            byte[] lengthAfterRecordHeaderAsBytes = ByteUtils.shortToByteArr(lengthAfterRecordHeader);
            messageBytes[3] = lengthAfterRecordHeaderAsBytes[0];
            messageBytes[4] = lengthAfterRecordHeaderAsBytes[1];
            lengthAfterHandshakeHeader = messageBytes.length - 9;
            messageBytes[6] = (byte) (lengthAfterHandshakeHeader >> 16);
            messageBytes[7] = (byte) (lengthAfterHandshakeHeader / 128);
            messageBytes[8] = (byte) (lengthAfterHandshakeHeader % 128);
            return new HelloMessage(this);
        }
        /*
        Fills the CipherSuite Array by using the bytes as ordinals
         */
        private void fillCipherSuitesFromBytes() {
            cipherSuites = new CipherSuite[cipherSuitesLength];
            for (int i = 0; i < cipherSuitesLength; i++) {
                cipherSuites[i] = CipherSuite.values()[cipherSuiteBytes[i]];
            }
        }
    }
}
