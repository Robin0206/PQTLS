package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.implementations.EncryptedExtensions;
import messages.implementations.WrappedRecord;
import org.bouncycastle.util.Strings;
import statemachines.State;
import statemachines.client.ClientStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

public class SendEncryptedExtensionsState implements State {
    private ServerStateMachine stateMachine;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return new WrappedRecord(
                new EncryptedExtensions(new PQTLSExtension[]{}),
                (byte)0x08,
                CryptographyModule.keys.byteArrToSymmetricKey(stateMachine.sharedSecretHolder.getServerHandShakeSecret(), getSymmetricCipherNameFromCipherSuite()),
                stateMachine.sharedSecretHolder.getServerHandShakeIVAndIncrement(),
                stateMachine.preferredCipherSuite
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
    public void setStateMachine(ClientStateMachine stateMachine) {

    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return true;
    }


    private String getSymmetricCipherNameFromCipherSuite() {
        String[] cipherSuiteContentSplit = Strings.split(stateMachine.preferredCipherSuite.name(), '_');
        for (int i = 0; i < cipherSuiteContentSplit.length; i++) {
            if (Objects.equals(cipherSuiteContentSplit[i], "WITH")) {
                stateMachine.sharedSecretHolder.setSymmetricAlgName(cipherSuiteContentSplit[i + 1]);
                return cipherSuiteContentSplit[i + 1];
            }
        }
        return null;
    }
}
