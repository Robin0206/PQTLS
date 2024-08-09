package messages.messageConverter;

import crypto.CryptographyModule;
import crypto.SharedSecret;
import messages.PQTLSMessage;
import messages.implementations.HelloMessage;
import messages.implementations.WrappedRecord;
import messages.implementations.alerts.AlertDescription;
import messages.implementations.alerts.AlertLevel;
import messages.implementations.alerts.PQTLSAlertMessage;
import misc.Constants;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;


public abstract class PQTLSMessageConverter {

    protected final SharedSecret sharedSecret;

    public PQTLSMessageConverter(ClientStateMachine statemachine) {
        this.sharedSecret = statemachine.getSharedSecret();
    }

    public PQTLSMessageConverter(ServerStateMachine statemachine) {
        this.sharedSecret = statemachine.getSharedSecret();
    }

    public PQTLSMessage convertMessage(byte[] messageByteBuffer) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, NoSuchProviderException, InvalidKeyException {
        if (isHelloMessage(messageByteBuffer)) {
            return new HelloMessage.HelloBuilder().fromBytes(messageByteBuffer).build();
        } else {// if its not an Hellomessage it must be an wrapped record
            try{
                WrappedRecord message = new WrappedRecord(
                        messageByteBuffer,
                        CryptographyModule.keys.byteArrToSymmetricKey(
                                getHandshakeSecret(),
                                sharedSecret.getSymmetricalAlgName()
                        ),
                        getIVAndIncrement(),
                        sharedSecret.getCipherSuite()
                );
                return message;
            }catch (Exception e){// if it cant be converted into an wrapped record, return an internal error alert
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
}
