package statemachines.client;

import crypto.CryptographyModule;
import crypto.SharedSecretHolder;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.implementations.HelloMessage;
import messages.implementations.NullMessage;
import misc.ByteUtils;
import misc.Constants;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import statemachines.PQTLSStateMachine;
import statemachines.State;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Objects;

/**
 * @author Robin Kroker
 * State responsible for calculating the shared Secret after the Hello Messages.
 * It expects the ServerHelloMessage as an argument to setPreviousMessage.
 * The next Method returns the WaitingForEncryptedExtensionsState.
 */

public class ClientCalcSharedSecretState implements State {
    private HelloMessage serverHelloMessage;
    private ClientStateMachine stateMachine;
    private KeyShareExtension serverHelloKeyShareExtension;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        setStateMachineChosenCipherSuite();
        setStateMachineChosenSymmetricAlgorithm();
        setServerHelloKeyShareExtension();
        setStateMachineChosenCurveAndItsKeyIndex();
        setStateMachineSharedSecret();
    }

    private void setServerHelloKeyShareExtension() {
        PQTLSExtension[] extensions = serverHelloMessage.getExtensions();
        for (PQTLSExtension extension : extensions) {
            if (extension.getIdentifier() == Constants.EXTENSION_IDENTIFIER_KEY_SHARE) {
                serverHelloKeyShareExtension = (KeyShareExtension) extension;
            }
        }
    }

    private void setStateMachineChosenCurveAndItsKeyIndex() {
        stateMachine.setChosenCurve(serverHelloKeyShareExtension.getCurveIdentifier());
        for (int i = 0; i < stateMachine.getSupportedCurves().length; i++) {
            if (stateMachine.getSupportedCurves()[i] == stateMachine.getChosenCurve()) {
                stateMachine.chosenCurveKeyIndex = i;
            }
        }
    }

    private void setStateMachineSharedSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ArrayList<Byte> sharedSecretBuffer = new ArrayList<>();

        //add the ecSharedSecret to the buffer
        byte[] ecSharedSecret = CryptographyModule.keys.generateECSharedSecret(
                stateMachine.ecKeyPairs[stateMachine.chosenCurveKeyIndex].getPrivate(),
                getECPublicKeyFromServerHello(),
                stateMachine.symmetricAlgorithm
        );
        for (byte b : ecSharedSecret) {
            sharedSecretBuffer.add(b);
        }

        // add the hybrid keys
        byte[][] serverHelloKeys = serverHelloKeyShareExtension.getKeys();
        if (cipherSuiteUsesFrodoKEM() && cipherSuiteUsesKyberKEM()) {
            byte[] frodoSharedSecret = CryptographyModule.keys.decapsulateSecret(
                    stateMachine.frodoKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 2],
                    "Frodo",
                    stateMachine.symmetricAlgorithm
            ).getEncoded();
            for (byte b : frodoSharedSecret) {
                sharedSecretBuffer.add(b);
            }
            byte[] kyberSharedSecret = CryptographyModule.keys.decapsulateSecret(
                    stateMachine.kyberKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 1],
                    "Kyber",
                    stateMachine.symmetricAlgorithm
            ).getEncoded();
            for (byte b : kyberSharedSecret) {
                sharedSecretBuffer.add(b);
            }
        } else if (cipherSuiteUsesFrodoKEM()) {
            byte[] frodoSharedSecret = CryptographyModule.keys.decapsulateSecret(
                    stateMachine.frodoKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 1],
                    "Frodo",
                    stateMachine.symmetricAlgorithm
            ).getEncoded();
            for (byte b : frodoSharedSecret) {
                sharedSecretBuffer.add(b);
            }
        } else if (cipherSuiteUsesKyberKEM()) {
            byte[] kyberSharedSecret = CryptographyModule.keys.decapsulateSecret(
                    stateMachine.kyberKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 1],
                    "Kyber",
                    stateMachine.symmetricAlgorithm
            ).getEncoded();
            for (byte b : kyberSharedSecret) {
                sharedSecretBuffer.add(b);
            }
        }
        byte[] concatenatedMessages = Arrays.concatenate(new byte[][]{
                stateMachine.getMessages().get(0).getBytes(),
                stateMachine.getMessages().get(1).getBytes()
        });
        byte[] sharedSecret = ByteUtils.toByteArray(sharedSecretBuffer);
        stateMachine.setSharedSecretHolder(
                new SharedSecretHolder(
                        sharedSecret,
                        concatenatedMessages,
                        stateMachine.getMessages().get(0).getBytes(),
                        serverHelloMessage.getCipherSuites()[0]
                )
        );
    }

    private PublicKey getECPublicKeyFromServerHello() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return CryptographyModule.keys.byteArrToPublicKey(
                serverHelloKeyShareExtension.getKeys()[0],
                "ECDH",
                "BC"
        );
    }

    private void setStateMachineChosenSymmetricAlgorithm() {
        String[] cipherSuiteContentSplit = Strings.split(stateMachine.getChosenCipherSuite().name(), '_');
        for (int i = 0; i < cipherSuiteContentSplit.length; i++) {
            if (Objects.equals(cipherSuiteContentSplit[i], "WITH")) {
                stateMachine.symmetricAlgorithm = cipherSuiteContentSplit[i + 1];
                return;
            }
        }
    }

    private void setStateMachineChosenCipherSuite() {
        stateMachine.setChosenCipherSuite(serverHelloMessage.getCipherSuites()[0]);
    }


    @Override
    public PQTLSMessage getMessage() {
        return new NullMessage();
    }

    @Override
    public State next() {
        return new WaitingForEncryptedExtensionsState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.serverHelloMessage = (HelloMessage) message;
    }

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
        this.stateMachine = (ClientStateMachine) stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }


    private boolean cipherSuiteUsesKyberKEM() {
        return stateMachine.getChosenCipherSuite().ordinal() >= 5;
    }

    private boolean cipherSuiteUsesFrodoKEM() {
        return stateMachine.getChosenCipherSuite().ordinal() < 5 || stateMachine.getChosenCipherSuite().ordinal() > 8;
    }
}
