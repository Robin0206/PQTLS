package messages.implementations;

import crypto.CipherSuite;
import messages.Message;
import messages.extensions.PQTLSExtension;
import org.bouncycastle.tls.SessionID;
import org.bouncycastle.util.Arrays;

import java.security.SecureRandom;
import java.security.cert.Extension;

//Builder Pattern
public class ClientHelloMessage implements Message {

    //Constructor gets only used in the builder
    private ClientHelloMessage(ClientHelloBuilder builder){
        this.protocolVersion = builder.protocolVersion;
        this.lengthAfterRecordHeader = builder.lengthAfterRecordHeader;
        this.lengthAfterHandshakeHeader = builder.lengthAfterHandshakeHeader;
        this.clientRandom = builder.clientRandom;
        this.sessionIDLength = builder.sessionIDLength;
        this.sessionID = builder.sessionID;
        this.cipherSuitesLength = builder.cipherSuitesLength;
        this.cipherSuites = builder.cipherSuites;
        this.extensionsLength = builder.extensionsLength;
        this.extensions = builder.extensions;
        this.extensionBytes = builder.extensionBytes;
        this.messageBytes = builder.messageBytes;
    }

    public boolean equals(ClientHelloMessage message){
        return (this.protocolVersion == message.protocolVersion &&
            this.lengthAfterRecordHeader == message.lengthAfterRecordHeader &&
            this.lengthAfterHandshakeHeader == message.lengthAfterHandshakeHeader &&
            this.clientRandom == message.clientRandom &&
            this.sessionIDLength == message.sessionIDLength &&
            this.sessionID == message.sessionID &&
            this.cipherSuitesLength == message.cipherSuitesLength &&
            this.cipherSuites == message.cipherSuites &&
            this.extensionsLength == message.extensionsLength &&
            java.util.Arrays.equals(this.extensions, message.extensions) || (message.extensions.length == 0 && this.extensions.length == 0) &&
                java.util.Arrays.equals(this.extensionBytes, message.extensionBytes) || (message.extensionBytes.length == 0 && this.extensionBytes.length == 0)&&
            java.util.Arrays.equals(this.messageBytes, message.messageBytes)
        );
    }
    //record header
    private final byte recordType = 0x16;
    private final short protocolVersion;
    private final short lengthAfterRecordHeader;

    //handshake header
    private final byte handShakeMessageType = 0x01;
    private final int lengthAfterHandshakeHeader;

    //client version
    private final byte[] legacyVersion = {0x03,0x03}; // https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2 [S. 29, Z. 1-8]

    //client random
    private final byte[] clientRandom;// 32 bytes

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


    //TODO
    @Override
    public void printVerbose() {
        System.out.println("==================Client Hello==================");
        System.out.println("RecordType:      " + recordType);
        System.out.println("ProtocolVersion: " + protocolVersion);
        System.out.println("LengthAfterRecordHeader: " + lengthAfterRecordHeader);
        System.out.println("HandShakeMessageType: " + handShakeMessageType);
        System.out.println("lengthAfterHandshakeHeader: " + lengthAfterHandshakeHeader);
        System.out.println("LegacyVersion: " + java.util.Arrays.toString(legacyVersion));
        System.out.println("Client Random: " + java.util.Arrays.toString(clientRandom));
        System.out.println("SessionIDLength: " + sessionIDLength);
        System.out.println("SessionID: " + java.util.Arrays.toString(sessionID));
        System.out.println("CipherSuiteLength: " + cipherSuitesLength);
        System.out.println("______CipherSuites______");
        for (int i = 0; i < cipherSuitesLength; i++) {
            System.out.println("\t" + cipherSuites[i].name());
        }
        System.out.println("CompressionMethodsLength: " + compressionMethodsLength);
        System.out.println("CompressionMethods: " + compressionMethods);
        System.out.println("ExtensionsLength: " + extensionsLength);
        System.out.println("_______Extensions_______");
        for (int i = 0; i < extensionsLength; i++) {
            System.out.println(extensions[i].toString());
        }
        System.out.println("MessageBytes: " + java.util.Arrays.toString(messageBytes));
    }
    @Override
    public byte[] getBytes() {
        return messageBytes;
    }
    public double getProtocolVersion() {
        return this.protocolVersion;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public static class ClientHelloBuilder{
        //record header
        private short protocolVersion;
        private short lengthAfterRecordHeader;

        //handshake header
        private int lengthAfterHandshakeHeader;

        //client random
        private byte[] clientRandom;// 32 bytes

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
        private boolean protocolVersionSet = false;
        private boolean sessionIDSet = false;
        private boolean cipherSuitesSet = false;
        private boolean extensionsSet = false;
        private boolean clientRandomSet = false;

        public ClientHelloBuilder protocolVersion(short protocolVersion){
            this.protocolVersion = protocolVersion;
            this.protocolVersionSet = true;
            return this;
        }
        public ClientHelloBuilder sessionID(byte[] sessionID){
            this.sessionID = sessionID;
            this.sessionIDLength = (byte) sessionID.length;
            this.sessionIDSet = true;
            return this;
        }
        public ClientHelloBuilder cipherSuites(CipherSuite[] cipherSuites){
            if(cipherSuites.length == 0){
                throw new IllegalArgumentException("There must be at least one cipher-suite");
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
        public ClientHelloBuilder extensions(PQTLSExtension[] extensions){
            this.extensions = extensions;
            this.extensionBytes = new byte[]{};
            for(PQTLSExtension extension : extensions){
                this.extensionBytes = Arrays.concatenate(this.extensionBytes, extension.getBytes());
            }
            this.extensionsLength = (short) this.extensionBytes.length;
            this.extensionsSet = true;
            return this;
        }
        public ClientHelloMessage build(){
            if(!extensionsSet){
                throw new IllegalArgumentException("Extensions not set");
            }else if(!cipherSuitesSet){
                throw new IllegalArgumentException("CipherSuites not set");
            }else if(!sessionIDSet){
                throw new IllegalArgumentException("SessionID not set");
            }else if(!protocolVersionSet){
                throw new IllegalArgumentException("ProtocolVersion not set");
            }
            if(!clientRandomSet){
                this.clientRandom = new byte[32];
                SecureRandom rand = new SecureRandom();
                rand.nextBytes(clientRandom);
            }
            //fill messageBytes
            this.messageBytes = Arrays.concatenate(new byte[][]{
                    {0x16, (byte) (this.protocolVersion >> 8), (byte) (this.protocolVersion)},// record header
                    {0x00, 0x00}, // number of following bytes
                    {0x01}, // stands for client hello
                    {0x00, 0x00, 0x00},// number of following bytes
                    {0x03, 0x03},// client version
                    clientRandom,
                    {sessionIDLength},
                    sessionID,
                    {cipherSuitesLength},
                    cipherSuiteBytes,
                    {0x01, 0x00}, // compression methods
                    {(byte)(extensionsLength >> 8), (byte)extensionsLength}, // extensions length
                    extensionBytes
            });
            //calculate lengths of bytes after record header and bytes after handshake header
            lengthAfterRecordHeader = (short)(messageBytes.length - 5);
            messageBytes[3] = (byte)(lengthAfterRecordHeader >> 8);
            messageBytes[4] = (byte)lengthAfterRecordHeader;
            lengthAfterHandshakeHeader = messageBytes.length - 9;
            messageBytes[6] = (byte)(lengthAfterHandshakeHeader >> 16);
            messageBytes[7] = (byte)(lengthAfterHandshakeHeader >> 8);
            messageBytes[8] = (byte)(lengthAfterHandshakeHeader);
            return new ClientHelloMessage(this);
        }
        public ClientHelloBuilder fromBytes(byte[] messageBytes){
            if(extensionsSet){
                throw new IllegalArgumentException("Extensions already set");
            }else if(cipherSuitesSet){
                throw new IllegalArgumentException("CipherSuites already set");
            }else if(sessionIDSet){
                throw new IllegalArgumentException("SessionID already set");
            }else if(protocolVersionSet){
                throw new IllegalArgumentException("ProtocolVersion already set");
            }
            protocolVersion = (short)((messageBytes[1] << 8) + messageBytes[2]);
            lengthAfterRecordHeader = (short)((messageBytes[4] << 8) + messageBytes[5]);
            lengthAfterHandshakeHeader = (int) messageBytes[6] << 16 + messageBytes[6] << 8 + messageBytes[7];
            clientRandom = new byte[32];
            System.arraycopy(
                    messageBytes, 
                    11, 
                    clientRandom,
                    0, 
                    clientRandom.length
            );
            clientRandomSet = true;
            sessionIDLength = messageBytes[11 + clientRandom.length];
            sessionID = new byte[sessionIDLength];
            System.arraycopy(
                    messageBytes, 
                    12 + clientRandom.length, 
                    sessionID,
                    0, 
                    sessionIDLength);
            cipherSuitesLength = messageBytes[12 + clientRandom.length + sessionID.length];
            cipherSuiteBytes = new byte[cipherSuitesLength];
            System.arraycopy(
                    messageBytes, 
                    13 + clientRandom.length + sessionID.length, cipherSuiteBytes, 
                    0, 
                    cipherSuitesLength
            );
            fillCipherSuitesFromBytes();
            extensionsLength =
                    (short) ((messageBytes[15 + clientRandom.length + sessionIDLength + cipherSuitesLength ] << 8)
                                        + ((messageBytes[16 + clientRandom.length + sessionIDLength + cipherSuitesLength ])));
            extensionBytes = new byte[extensionsLength];
            System.arraycopy(
                    messageBytes,
                    17 + clientRandom.length + sessionIDLength + cipherSuitesLength,
                    extensionBytes,
                    0,
                    extensionsLength
            );
            fillExtensionsFromBytes();
            this.messageBytes = messageBytes.clone();
            protocolVersionSet = true;
            cipherSuitesSet = true;
            sessionIDSet = true;
            extensionsSet = true;
            return this;
        }

        private void fillExtensionsFromBytes() {
            extensions = new PQTLSExtension[0];
            byte[][] extensionsSplit = splitExtensions(extensionBytes);
        }
        //TODO
        private byte[][] splitExtensions(byte[] extensionBytes) {
            return new byte[][]{{}};
        }

        private void fillCipherSuitesFromBytes() {
            cipherSuites = new CipherSuite[cipherSuitesLength];
            for(int i = 0; i < cipherSuitesLength; i++){
                cipherSuites[i] = CipherSuite.values()[cipherSuiteBytes[i]];
            }
        }
    }
}
