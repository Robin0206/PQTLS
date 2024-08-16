package messages.implementations;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import misc.ByteUtils;
import misc.Constants;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author Robin Kroker
 */
public class FinishedMessage implements PQTLSMessage {
    byte[] messageBytes;
    public FinishedMessage(byte[] messageBytes) {
        this.messageBytes = messageBytes;
    }

    /**
     * Usage taken from https://www.rfc-editor.org/rfc/rfc8446 page 62
     * Usage for Server:
     * concatenatedMessages: Client-Hello -> EncryptedExtensions, Key: serverHandshakeTrafficSecret
     * Usage for Client:
     * concatenatedMessages: Client-Hello -> Server-Finished, Key: clientHandshakeTrafficSecret
     */
    public FinishedMessage(ArrayList<byte[]> concatenatedMessages, byte[] baseKey, String hashName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] finishedData = calculateVerifyData(concatenatedMessages, baseKey, hashName);
        fillMessageBytes(finishedData);
    }

    private void fillMessageBytes(byte[] finishedData) {
        ArrayList<Byte> buffer = new ArrayList<>();
        buffer.add(Constants.HANDSHAKE_TYPE_FINISHED);
        byte[] numOfFollowingBytes = ByteUtils.intToByteArray3(finishedData.length);
        for(byte b : numOfFollowingBytes){
            buffer.add(b);
        }
        for(byte b : finishedData){
            buffer.add(b);
        }
        messageBytes = ByteUtils.toByteArray(buffer);
    }

    /**
     * calculation taken from https://www.rfc-editor.org/rfc/rfc8446 page 72
     */
    private byte[] calculateVerifyData(ArrayList<byte[]> concatenatedMessages, byte[] baseKey, String hashName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] finishedKey = CryptographyModule.hashing.hkdfExpandLabel(
                baseKey,
                "hMac"+ hashName,
                "finished".getBytes(),
                "".getBytes(),
                48
        );
        return CryptographyModule.hashing.hMac(
                "hMac"+ hashName,
                ByteUtils.flatten(concatenatedMessages),
                baseKey
        );
    }
    
    public byte[] getVerifyData(){
        byte[] verifyData = new byte[messageBytes.length - 4];
        System.arraycopy(
                messageBytes,
                4,
                verifyData,
                0,
                verifyData.length
        );
        return verifyData;
    }


    @Override
    public byte[] getBytes() {
        return messageBytes;
    }

    @Override
    public void printVerbose() {
        //Not needed because this message will only be send encrypted
    }

    @Override
    public boolean equals(PQTLSMessage messageToCast) {
        FinishedMessage message = (FinishedMessage) messageToCast;
        return Arrays.equals(this.messageBytes, message.messageBytes);
    }
}
