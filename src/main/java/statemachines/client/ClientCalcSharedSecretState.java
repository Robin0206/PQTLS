package statemachines.client;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.implementations.HelloMessage;
import messages.implementations.NullMessage;
import misc.Constants;
import org.bouncycastle.util.Strings;
import statemachines.State;
import statemachines.server.ServerStateMachine;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Objects;

public class ClientCalcSharedSecretState extends State {
    private HelloMessage serverHelloMessage;
    private ClientStateMachine stateMachine;
    private KeyShareExtension serverHelloKeyShareExtension;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        setStateMachineChosenCipherSuite();
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
            if(stateMachine.curveIdentifiers[i] == stateMachine.chosenCurve){
                stateMachine.chosenCurveKeyIndex = i;
            }
        }
    }

    private void setStateMachineSharedSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ArrayList<Byte> sharedSecretBuffer = new ArrayList<>();
        byte[] ecSharedSecret = CryptographyModule.generateECSharedSecret(
                    stateMachine.ecKeyPairs[stateMachine.chosenCurveKeyIndex].getPrivate(),
                    getECPublicKeyFromServerHello(),
                    getSymmetricCipherNameFromCipherSuite()
                );
        for (byte b : ecSharedSecret){
            sharedSecretBuffer.add(b);
        }
        byte[][] serverHelloKeys = serverHelloKeyShareExtension.getKeys();
        if(cipherSuiteUsesFrodoKEM() && cipherSuiteUsesKyberKEM()){
            byte[] frodoSharedSecret = CryptographyModule.decapsulateSecret(
                    stateMachine.frodoKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 2],
                    "Frodo",
                    getSymmetricCipherNameFromCipherSuite()
            ).getEncoded();
            for (byte b : frodoSharedSecret){
                sharedSecretBuffer.add(b);
            }
            byte[] kyberSharedSecret = CryptographyModule.decapsulateSecret(
                    stateMachine.frodoKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 1],
                    "Kyber",
                    getSymmetricCipherNameFromCipherSuite()
            ).getEncoded();
            for (byte b : kyberSharedSecret){
                sharedSecretBuffer.add(b);
            }
        }
        else if(cipherSuiteUsesFrodoKEM()){
            byte[] frodoSharedSecret = CryptographyModule.decapsulateSecret(
                    stateMachine.frodoKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 1],
                    "Frodo",
                    getSymmetricCipherNameFromCipherSuite()
            ).getEncoded();
            for (byte b : frodoSharedSecret){
                sharedSecretBuffer.add(b);
            }
        } else if(cipherSuiteUsesKyberKEM()){
            byte[] kyberSharedSecret = CryptographyModule.decapsulateSecret(
                    stateMachine.kyberKey.getPrivate(),
                    serverHelloKeys[serverHelloKeys.length - 1],
                    "Kyber",
                    getSymmetricCipherNameFromCipherSuite()
            ).getEncoded();
            for (byte b : kyberSharedSecret){
                sharedSecretBuffer.add(b);
            }
        }
        stateMachine.sharedSecret = new byte[sharedSecretBuffer.size()];
        for (int i = 0; i < stateMachine.sharedSecret.length; i++) {
            stateMachine.sharedSecret[i] = sharedSecretBuffer.get(i);
        }
    }



    private PublicKey getECPublicKeyFromServerHello() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return CryptographyModule.byteArrToPublicKey(
                serverHelloKeyShareExtension.getKeys()[0],
                "ECDH",
                "BC"
        );
    }

    private String getSymmetricCipherNameFromCipherSuite() {
        String[] cipherSuiteContentSplit = Strings.split(stateMachine.chosenCipherSuite.name(), '_');
        for (int i = 0; i < cipherSuiteContentSplit.length; i++) {
            if(Objects.equals(cipherSuiteContentSplit[i], "WITH")){
                return cipherSuiteContentSplit[i+1];
            }
        }
        return null;
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
        return null;
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.serverHelloMessage = (HelloMessage)message;
    }

    @Override
    public void setStateMachine(ClientStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {
    }
    private boolean cipherSuiteUsesKyberKEM() {
        return stateMachine.chosenCipherSuite.ordinal() != 0 && !cipherSuiteUsesFrodoKEM();
    }

    private boolean cipherSuiteUsesFrodoKEM() {
        return stateMachine.chosenCipherSuite.ordinal() < 7 || stateMachine.chosenCipherSuite.ordinal() > 12;
    }
}
