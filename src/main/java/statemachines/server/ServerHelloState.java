package statemachines.server;

import crypto.CryptographyModule;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SupportedGroupsExtension;
import messages.implementations.HelloMessage;
import misc.Constants;
import org.bouncycastle.util.Strings;
import statemachines.State;
import statemachines.client.ClientStateMachine;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Objects;

public class ServerHelloState extends State {
    ServerStateMachine stateMachine;
    private HelloMessage clientHelloMessage;
    private PublicKey clientPublicKeyFrodo;
    private PublicKey clientPublicKeyKyber;
    private PublicKey clientPublicKeyEC;
    private KeyShareExtension keyShareExtension;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        setStateMachinePreferredCipherSuite();
        setStateMachinePreferredCurve();
        setStateMachineSessionID();
        setStateMachineRandom();
        extractPQKeyPairsFromClientHelloMessage();
        extractECPublicKeyFromClientHelloMessage();
        setStateMachineKeyPairs();
        generateKeyShareExtension();
        setStateMachineSharedSecret();
    }

    private void extractECPublicKeyFromClientHelloMessage() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyShareExtension clientKeyShare = getKeyShareExtensionFromClientHello();
        int index = getPreferredCurveIndexInKeyShareExtension();
        clientPublicKeyEC = CryptographyModule.byteArrToPublicKey(
                clientKeyShare.getKeys()[index],
                "ECDH",
                "BC"
        );
    }

    private int getPreferredCurveIndexInKeyShareExtension() {
        CurveIdentifier[] clientSupportedCurves = getSupportedCurvesByClient();
        for (int i = 0; i < clientSupportedCurves.length; i++) {
            if(clientSupportedCurves[i] == stateMachine.preferredCurveIdentifier){
                return i;
            }
        }
        return -1;
    }


    private void setStateMachineSharedSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        ArrayList<Byte> sharedSecretBuffer = new ArrayList<>();
        byte[] ecSharedSecret = CryptographyModule.generateECSharedSecret(
                stateMachine.ecKeyPair.getPrivate(),
                clientPublicKeyEC,
                getSymmetricCipherNameFromCipherSuite()
        );
        for (byte b : ecSharedSecret){
            sharedSecretBuffer.add(b);
        }
        if(cipherSuiteUsesFrodoKEM()){
            byte[] frodoSharedSecret = stateMachine.frodoEncapsulatedSecret.getEncoded();
            for (byte b : frodoSharedSecret){
                sharedSecretBuffer.add(b);
            }
        }
        if(cipherSuiteUsesKyberKEM()){
            byte[] kyberSharedSecret = stateMachine.kyberEncapsulatedSecret.getEncoded();
            for (byte b : kyberSharedSecret){
                sharedSecretBuffer.add(b);
            }
        }
        stateMachine.sharedSecret = new byte[sharedSecretBuffer.size()];
        for (int i = 0; i < stateMachine.sharedSecret.length; i++) {
            stateMachine.sharedSecret[i] = sharedSecretBuffer.get(i);
        }
    }

    private String getSymmetricCipherNameFromCipherSuite() {
        String[] cipherSuiteContentSplit = Strings.split(stateMachine.preferredCipherSuite.name(), '_');
        for (int i = 0; i < cipherSuiteContentSplit.length; i++) {
            if(Objects.equals(cipherSuiteContentSplit[i], "WITH")){
                return cipherSuiteContentSplit[i+1];
            }
        }
        return null;
    }

    private void generateKeyShareExtension() {
        ArrayList<byte[]> keyBuffer = new ArrayList<>();
        keyBuffer.add(stateMachine.ecKeyPair.getPublic().getEncoded());
        if(cipherSuiteUsesFrodoKEM()){
            keyBuffer.add(stateMachine.frodoEncapsulatedSecret.getEncapsulation());
        }
        if(cipherSuiteUsesKyberKEM()){
            keyBuffer.add(stateMachine.kyberEncapsulatedSecret.getEncapsulation());
        }
        byte[][] keysArray = new byte[keyBuffer.size()][];
        for (int i = 0; i < keysArray.length; i++) {
            keysArray[i] = keyBuffer.get(i);
        }
        keyShareExtension =  new KeyShareExtension(keysArray, stateMachine.preferredCurveIdentifier);

    }
    private void extractPQKeyPairsFromClientHelloMessage() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyShareExtension keyShare = getKeyShareExtensionFromClientHello();
        byte[][] keys = keyShare.getKeys();
        if(clientHelloCipherSuitesContainOneWithFrodoKEM() && clientHelloCipherSuitesContainOneWithKyberKEM()){
            clientPublicKeyFrodo = CryptographyModule.byteArrToPublicKey(
                    keys[keys.length-2],
                    "Frodo",
                    "BCPQC"
            );
            clientPublicKeyKyber = CryptographyModule.byteArrToPublicKey(
                    keys[keys.length-1],
                    "Kyber",
                    "BCPQC"
            );
        }else if(clientHelloCipherSuitesContainOneWithFrodoKEM()){
            clientPublicKeyFrodo = CryptographyModule.byteArrToPublicKey(
                    keys[keys.length-1],
                    "Frodo",
                    "BCPQC"
            );
        }else if(clientHelloCipherSuitesContainOneWithKyberKEM()){
            clientPublicKeyKyber = CryptographyModule.byteArrToPublicKey(
                    keys[keys.length-1],
                    "Kyber",
                    "BCPQC"
            );
        }
    }

    private KeyShareExtension getKeyShareExtensionFromClientHello() {
        PQTLSExtension[] extensions = clientHelloMessage.getExtensions();
        for(PQTLSExtension extension : extensions){
            if(extension.getIdentifier() == Constants.EXTENSION_IDENTIFIER_KEY_SHARE){
                return (KeyShareExtension)extension;
            }
        }
        //TODO
        // Will be removed later
        throw new RuntimeException("Client-Hello didnt contain Key-Share Extension");
    }

    //TODO
    // will be rewritten with the use of a keystore
    private void setStateMachineKeyPairs() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        stateMachine.ecKeyPair = CryptographyModule.generateECKeyPair(stateMachine.preferredCurveIdentifier);
        if(cipherSuiteUsesFrodoKEM()){
            stateMachine.frodoEncapsulatedSecret = CryptographyModule.generateEncapsulatedSecret(
                    clientPublicKeyFrodo,
                    "Frodo",
                    getSymmetricCipherNameFromCipherSuite()
            );
        }
        if(cipherSuiteUsesKyberKEM()){
            stateMachine.kyberEncapsulatedSecret = CryptographyModule.generateEncapsulatedSecret(
                    clientPublicKeyKyber,
                    "Kyber",
                    getSymmetricCipherNameFromCipherSuite()
            );
        }
    }

    private boolean cipherSuiteUsesKyberKEM() {
        return stateMachine.preferredCipherSuite.ordinal() >= 7 && stateMachine.preferredCipherSuite.ordinal() <= 12;
    }

    private boolean cipherSuiteUsesFrodoKEM() {
        return stateMachine.preferredCipherSuite.ordinal() < 7 || stateMachine.preferredCipherSuite.ordinal() > 12;
    }

    private boolean clientHelloCipherSuitesContainOneWithFrodoKEM(){
        for(CipherSuite cipherSuite: clientHelloMessage.getCipherSuites()){
            if(cipherSuite.ordinal() < 7 || cipherSuite.ordinal() > 12){
                return true;
            }
        }
        return false;
    }
    private boolean clientHelloCipherSuitesContainOneWithKyberKEM(){
        for(CipherSuite cipherSuite: clientHelloMessage.getCipherSuites()){
            if(cipherSuite.ordinal() >= 7 && cipherSuite.ordinal() <= 12){
                return true;
            }
        }
        return false;
    }
    private void setStateMachinePreferredCurve() {
        CurveIdentifier[] supportedCurvesByServer = stateMachine.supportedCurves;
        CurveIdentifier[] supportedCurvesByClient = getSupportedCurvesByClient();
        for(CurveIdentifier curveIdentifierClient : supportedCurvesByClient){
            for(CurveIdentifier curveIdentifierServer : supportedCurvesByServer){
                if(curveIdentifierClient == curveIdentifierServer){
                    stateMachine.preferredCurveIdentifier = curveIdentifierClient;
                    return;
                }
            }
        }
    }

    private CurveIdentifier[] getSupportedCurvesByClient() {
        PQTLSExtension[] extensions = clientHelloMessage.getExtensions();
        for(PQTLSExtension extension : extensions){
            if(extension.getIdentifier() == Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS){
                return ((SupportedGroupsExtension)extension).getSupportedGroups();
            }
        }
        //TODO
        // Will be removed later
        throw new RuntimeException("Client-Hello didnt contain Supported Groups Extension");
    }


    private void setStateMachineRandom() {
        stateMachine.random = new byte[Constants.HELLO_MESSAGE_RANDOM_LENGTH];
        new SecureRandom().nextBytes(stateMachine.random);
    }

    private void setStateMachineSessionID() {
        stateMachine.sessionID = clientHelloMessage.getSessionID();
    }


    private void setStateMachinePreferredCipherSuite() {
        CipherSuite[] clientCipherSuites = clientHelloMessage
                .getCipherSuites();
        for (int i = 0; i < stateMachine.supportedCipherSuites.length; i++) {
            for (int j = 0; j < clientCipherSuites.length; j++) {
                if(stateMachine.supportedCipherSuites[i] == clientCipherSuites[i]){
                    //This if will always be reached since there is a mandatory cipher suite
                    stateMachine.preferredCipherSuite = clientCipherSuites[i];
                    return;
                }
            }
        }
    }


    @Override
    public PQTLSMessage getMessage() {
        return new HelloMessage.HelloBuilder()
                .extensions(new PQTLSExtension[]{keyShareExtension})
                .cipherSuites(new CipherSuite[]{stateMachine.preferredCipherSuite})
                .sessionID(stateMachine.sessionID)
                .LegacyVersion(new byte[]{0x03, 0x03})
                .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO)
                .random(stateMachine.random)
                .build();
    }

    @Override
    public State next() {
        return null;
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        clientHelloMessage = (HelloMessage) message;
    }

    @Override
    public void setStateMachine(ClientStateMachine stateMachine) {

    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }
}
