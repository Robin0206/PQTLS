package statemachines.client;

import crypto.CryptographyModule;
import crypto.SharedSecret;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.implementations.HelloMessage;
import messages.implementations.NullMessage;
import misc.ByteUtils;
import misc.Constants;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import statemachines.State;
import statemachines.server.ServerStateMachine;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Objects;

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
        stateMachine.chosenCurve = serverHelloKeyShareExtension.getCurveIdentifier();
        for (int i = 0; i < stateMachine.curveIdentifiers.length; i++) {
            if (stateMachine.curveIdentifiers[i] == stateMachine.chosenCurve) {
                stateMachine.chosenCurveKeyIndex = i;
            }
        }
    }

    private void setStateMachineSharedSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ArrayList<Byte> sharedSecretBuffer = new ArrayList<>();
        byte[] ecSharedSecret = CryptographyModule.keys.generateECSharedSecret(
                stateMachine.ecKeyPairs[stateMachine.chosenCurveKeyIndex].getPrivate(),
                getECPublicKeyFromServerHello(),
                stateMachine.symmetricAlgorithm
        );
        for (byte b : ecSharedSecret) {
            sharedSecretBuffer.add(b);
        }
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
                    stateMachine.frodoKey.getPrivate(),
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
                stateMachine.messages.get(0).getBytes(),
                stateMachine.messages.get(1).getBytes()
        });
        byte[] sharedSecret = ByteUtils.toByteArray(sharedSecretBuffer);
        stateMachine.sharedSecret = new SharedSecret(sharedSecret, "sha384", concatenatedMessages, stateMachine.messages.get(0).getBytes(), serverHelloMessage.getCipherSuites()[0]);
    }


    private PublicKey getECPublicKeyFromServerHello() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return CryptographyModule.keys.byteArrToPublicKey(
                serverHelloKeyShareExtension.getKeys()[0],
                "ECDH",
                "BC"
        );
    }

    private void setStateMachineChosenSymmetricAlgorithm() {
        String[] cipherSuiteContentSplit = Strings.split(stateMachine.chosenCipherSuite.name(), '_');
        for (int i = 0; i < cipherSuiteContentSplit.length; i++) {
            if (Objects.equals(cipherSuiteContentSplit[i], "WITH")) {
                stateMachine.symmetricAlgorithm = cipherSuiteContentSplit[i + 1];
                return;
            }
        }
    }

    private void setStateMachineChosenCipherSuite() {
        stateMachine.chosenCipherSuite = serverHelloMessage.getCipherSuites()[0];
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
    public void setStateMachine(ClientStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }


    private boolean cipherSuiteUsesKyberKEM() {
        return stateMachine.chosenCipherSuite.ordinal() != 0 && !cipherSuiteUsesFrodoKEM();
    }

    private boolean cipherSuiteUsesFrodoKEM() {
        return stateMachine.chosenCipherSuite.ordinal() < 5 || stateMachine.chosenCipherSuite.ordinal() > 8;
    }
}
