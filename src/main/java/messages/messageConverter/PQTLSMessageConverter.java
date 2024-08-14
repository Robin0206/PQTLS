package messages.messageConverter;

import crypto.CryptographyModule;
import crypto.SharedSecretHolder;
import messages.PQTLSMessage;
import messages.implementations.HelloMessage;
import messages.implementations.WrappedRecord;
import messages.implementations.alerts.AlertDescription;
import messages.implementations.alerts.AlertLevel;
import messages.implementations.alerts.PQTLSAlertMessage;
import misc.ByteUtils;
import misc.Constants;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.util.ArrayList;


public abstract class PQTLSMessageConverter {

    protected SharedSecretHolder sharedSecretHolder;

    public PQTLSMessageConverter(ClientStateMachine statemachine) {
        this.sharedSecretHolder = statemachine.getSharedSecret();
    }

    public PQTLSMessageConverter(ServerStateMachine statemachine) {
        this.sharedSecretHolder = statemachine.getSharedSecret();
    }

    public PQTLSMessage convertMessage(byte[] messageByteBuffer) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, NoSuchProviderException, InvalidKeyException {
        if (isHelloMessage(messageByteBuffer)) {
            return new HelloMessage.HelloBuilder().fromBytes(messageByteBuffer).build();
        } else {// if its not an Hellomessage it must be an wrapped record or an alert message
            try{
                WrappedRecord message = new WrappedRecord(
                        messageByteBuffer,
                        CryptographyModule.keys.byteArrToSymmetricKey(
                                getHandshakeSecret(),
                                sharedSecretHolder.getSymmetricalAlgName()
                        ),
                        getIVAndIncrement(),
                        sharedSecretHolder.getCipherSuite()
                );
                return message;
            }catch (Exception e){// if it cant be converted into an wrapped record, return an internal error alert
                e.printStackTrace();
                return new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.internal_error);
            }
        }
    }


    private boolean isHelloMessage(byte[] messageByteBuffer) {
        return messageByteBuffer[5] == Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO ||
                messageByteBuffer[5] == Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO;
    }

    protected abstract byte[] getIVAndIncrement();
    protected abstract byte[] getHandshakeSecret();
    static public byte[] readMessageFromStream(InputStream stream) throws IOException {
        byte[] header;
        header = readNBytesBlocking(stream, 5);
        short numOfFollowingBytes = ByteUtils.byteArrToShort(
                new byte[]{header[3], header[4]}
        );
        byte[] followingBytes;
        followingBytes = readNBytesBlocking(stream, numOfFollowingBytes);
        byte[] result = new byte[header.length + followingBytes.length];
        System.arraycopy(
                header,
                0,
                result,
                0,
                header.length
        );
        System.arraycopy(
                followingBytes,
                0,
                result,
                header.length,
                followingBytes.length
        );
        return result;
    }

    //this method doesnt return until there are n bytes in the stream
    static byte[] readNBytesBlocking(InputStream stream, int numOfBytes) throws IOException {
        ArrayList<Byte> buffer = new ArrayList<>();
        int remaining = numOfBytes;
        while(buffer.size() < numOfBytes){
            byte[] bytesRead = stream.readNBytes(remaining);
            for (int i = 0; i < bytesRead.length; i++) {
                buffer.add(bytesRead[i]);
                remaining--;
            }
        }
        return ByteUtils.toByteArray(buffer);
    }


    public void setSharedSecret(SharedSecretHolder sharedSecretHolder) {
        this.sharedSecretHolder = sharedSecretHolder;
    }
}
