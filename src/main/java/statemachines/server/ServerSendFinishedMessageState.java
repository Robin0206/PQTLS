package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.FinishedMessage;
import messages.implementations.WrappedRecord;
import misc.Constants;
import statemachines.PQTLSStateMachine;
import statemachines.State;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/**
 * @author Robin Kroker
This state is responsible for bulding the servers FinishedMessage
This State doesn't make use of any prior message.
(The Statemachine calls the setPreviousMessage method with an NullMessage
as an argument)
The method getMessage doesn't return any alert messages,
it always returns a wrapped FinishedMessage.
The method next returns the VerifyClientFinishedAndFinishSharedSecretCalculationState.
 */
public class ServerSendFinishedMessageState implements State {
    private ArrayList<byte[]> concatenatedMessages;
    private ServerStateMachine stateMachine;

    @Override
    public void calculate() {
        setConcatenatedMessages();
    }

    private void setConcatenatedMessages() {
        concatenatedMessages = new ArrayList<>();
        for(int i = 0; i < 3; i++){
            concatenatedMessages.add(stateMachine.getMessages().get(i).getBytes());
        }
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return new WrappedRecord(
                new FinishedMessage(
                        concatenatedMessages,
                        stateMachine.getSharedSecretHolder().getServerHandShakeSecret(),
                        stateMachine.getSharedSecretHolder().getHashName()
                ),
                Constants.HANDSHAKE_TYPE_FINISHED,
                CryptographyModule.keys.byteArrToSymmetricKey(
                        stateMachine.getSharedSecretHolder().getServerHandShakeSecret(),
                        stateMachine.getPreferredSymmetricAlgorithm()
                ),
                stateMachine.getSharedSecretHolder().getServerHandShakeIVAndIncrement(),
                stateMachine.getChosenCipherSuite()
        );
    }

    @Override
    public State next() {
        return new VerifyClientFinishedAndFinishSharedSecretCalculationState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {

    }

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
        this.stateMachine = (ServerStateMachine) stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }

}
