package messages.implementations;

import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.PQTLSExtensionFactory;
import misc.ByteUtils;
import misc.Constants;

import java.security.cert.Extension;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author Robin Kroker
 * Follows the structure detailed in https://www.rfc-editor.org/rfc/rfc8446 section 4.3.1
 * Since there are no extensions used after the key agreement this message is always empty
 * Also always sent as a wrapped record
 * Byte structure:
 * ||..identifier = 0x08..||..numOfFollowingExtensionBytes..||..extensionBytes..||
 * ||--------1 byte-------||-------------3 bytes------------||
 */
public class EncryptedExtensions implements PQTLSMessage{

    private final PQTLSExtension[] extensions;
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
        messageBytes[0] = Constants.HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS;
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

    @Override
    public boolean equals(PQTLSMessage messageToCast) {
        EncryptedExtensions message = (EncryptedExtensions) messageToCast;

        for (PQTLSExtension extension1 : extensions) {
            for (PQTLSExtension extension2 : message.extensions) {
                if(!Arrays.equals(extension1.getByteRepresentation(), extension2.getByteRepresentation())){
                    return false;
                }
            }
        }

        return
                Arrays.equals(messageBytes, message.messageBytes) &&
                Arrays.equals(extensionBytes, message.extensionBytes);
    }
}
