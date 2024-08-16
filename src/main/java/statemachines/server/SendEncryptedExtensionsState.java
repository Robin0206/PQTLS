package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.implementations.EncryptedExtensions;
import messages.implementations.WrappedRecord;
import org.bouncycastle.util.Strings;
import statemachines.PQTLSStateMachine;
import statemachines.State;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

/**
 * @author Robin Kroker
This State is responsible for building the EncryptedExtensionsMessage.
This State doesn't make use of any prior message.
(The Statemachine calls the setPreviousMessage method with an NullMessage
as an argument)
The method getMessage returns the wrapped EncryptedExtensions message
The method next returns the SendingCertificatesState
 */
public class SendEncryptedExtensionsState implements State {
    private ServerStateMachine stateMachine;

    @Override
    public void calculate() {
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return new WrappedRecord(
                new EncryptedExtensions(new PQTLSExtension[]{}),
                (byte)0x08,
                CryptographyModule.keys.byteArrToSymmetricKey(stateMachine.getSharedSecretHolder().getServerHandShakeSecret(), getSymmetricCipherNameFromCipherSuite()),
                stateMachine.getSharedSecretHolder().getServerHandShakeIVAndIncrement(),
                stateMachine.getChosenCipherSuite()
        );
    }

    @Override
    public State next() {
        return new SendingCertificatesState();
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
        return true;
    }


    private String getSymmetricCipherNameFromCipherSuite() {
        String[] cipherSuiteContentSplit = Strings.split(stateMachine.getChosenCipherSuite().name(), '_');
        for (int i = 0; i < cipherSuiteContentSplit.length; i++) {
            if (Objects.equals(cipherSuiteContentSplit[i], "WITH")) {
                stateMachine.getSharedSecretHolder().setSymmetricAlgName(cipherSuiteContentSplit[i + 1]);
                return cipherSuiteContentSplit[i + 1];
            }
        }
        return null;
    }
}
