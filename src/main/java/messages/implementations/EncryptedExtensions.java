package messages.implementations;

import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.PQTLSExtensionFactory;
import misc.ByteUtils;

import java.security.cert.Extension;
import java.util.ArrayList;
import java.util.Arrays;

// Format
// ||..identifier = 0x08..||..numOfFollowingExtensionBytes..||..extensionBytes..||
// ||--------1 byte-------||-------------3 bytes------------||
public class EncryptedExtensions implements PQTLSMessage{

    private PQTLSExtension[] extensions;
    private byte[] messageBytes;
    private byte[] extensionBytes;
    

    public EncryptedExtensions(byte[] messageBytes) {
        this.messageBytes = messageBytes;
        setExtensionBytesUsingMessageBytes();
        extensions = PQTLSExtensionFactory.generateMultipleFromBytes(extensionBytes);
    }

    public EncryptedExtensions(PQTLSExtension[] extensions){
        this.extensions = extensions;
        setExtensionBytesUsingExtensionsArray();
        setMessageBytes();
    }

    public boolean equals(EncryptedExtensions encryptedExtensions){
        return
                Arrays.equals(messageBytes, encryptedExtensions.messageBytes) &&
                Arrays.equals(extensionBytes, encryptedExtensions.extensionBytes)
        ;
    }

    private void setExtensionBytesUsingMessageBytes() {
        extensionBytes = new byte[messageBytes.length - 4];
        System.arraycopy(
                messageBytes,
                4,
                extensionBytes,
                0,
                messageBytes.length - 4
        );
    }

    private void setMessageBytes() {
        messageBytes = new byte[extensionBytes.length + 4];
        messageBytes[0] = 0x08;
        byte[] numOfFollowingBytes = ByteUtils.intToByteArray3(extensionBytes.length);
        messageBytes[1] = numOfFollowingBytes[0];
        messageBytes[2] = numOfFollowingBytes[1];
        messageBytes[3] = numOfFollowingBytes[2];
        System.arraycopy(extensionBytes, 0, messageBytes, 4, messageBytes.length - 4);
    }

    private void setExtensionBytesUsingExtensionsArray() {
        ArrayList<Byte> buffer = new ArrayList<>();
        for(PQTLSExtension extension : extensions){
            for(byte b : extension.getByteRepresentation()){
                buffer.add(b);
            }
        }
        extensionBytes = new byte[buffer.size()];
        for (int i = 0; i < extensionBytes.length; i++) {
            extensionBytes[i] = buffer.get(i);
        }
    }

    @Override
    public byte[] getBytes() {
        return messageBytes;
    }

    @Override
    public void printVerbose() {

    }
}
