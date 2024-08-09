package statemachines.server;

import crypto.CryptographyModule;
import crypto.SharedSecret;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SupportedGroupsExtension;
import messages.implementations.HelloMessage;
import messages.implementations.alerts.AlertDescription;
import messages.implementations.alerts.AlertLevel;
import messages.implementations.alerts.PQTLSAlertMessage;
import misc.ByteUtils;
import misc.Constants;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import statemachines.State;
import statemachines.client.ClientStateMachine;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Objects;

public class ServerHelloState implements State {
    ServerStateMachine stateMachine;
    private HelloMessage clientHelloMessage;
    private PublicKey clientPublicKeyFrodo;
    private PublicKey clientPublicKeyKyber;
    private PublicKey clientPublicKeyEC;
    private KeyShareExtension keyShareExtension;
    private PQTLSAlertMessage alertMessage;

    @Override
    public void calculate() throws Exception {//only throws the exception if the alertMessage isn't set
        try{
            setStateMachinePreferredCipherSuite();
            setStateMachinePreferredCurve();
            setStateMachineSessionID();
            setStateMachineRandom();
            extractPQKeyPairsFromClientHelloMessage();
            extractECPublicKeyFromClientHelloMessage();
            setStateMachineKeyPairs();
            generateKeyShareExtension();
            setStateMachineSharedSecret();
        }catch (Exception e){
            if(alertMessage == null){
                throw e;
            }
        }
    }

    private void extractECPublicKeyFromClientHelloMessage() throws Exception {
        KeyShareExtension clientKeyShare = getKeyShareExtensionFromClientHello();
        int index = getPreferredCurveIndexInKeyShareExtension();
        clientPublicKeyEC = CryptographyModule.keys.byteArrToPublicKey(
                clientKeyShare.getKeys()[index],
                "ECDH",
                "BC"
        );
    }

    private int getPreferredCurveIndexInKeyShareExtension() throws Exception {
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
        byte[] ecSharedSecret = CryptographyModule.keys.generateECSharedSecret(
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
        byte[] concatenatedMessages = Arrays.concatenate(new byte[][]{
                stateMachine.messages.getFirst().getBytes(),
                this.getMessage().getBytes()
        });
        byte[] sharedSecret = ByteUtils.toByteArray(sharedSecretBuffer);
        stateMachine.sharedSecret = new SharedSecret(sharedSecret, "sha384", concatenatedMessages, stateMachine.messages.getFirst().getBytes());
        stateMachine.sharedSecret.setSymmetricAlgName(stateMachine.getPreferredSymmetricAlgorithm());
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
    private void extractPQKeyPairsFromClientHelloMessage() throws Exception {
        KeyShareExtension keyShare = getKeyShareExtensionFromClientHello();
        byte[][] keys = keyShare.getKeys();
        if(clientHelloCipherSuitesContainOneWithFrodoKEM() && clientHelloCipherSuitesContainOneWithKyberKEM()){
            clientPublicKeyFrodo = CryptographyModule.keys.byteArrToPublicKey(
                    keys[keys.length-2],
                    "Frodo",
                    "BCPQC"
            );
            clientPublicKeyKyber = CryptographyModule.keys.byteArrToPublicKey(
                    keys[keys.length-1],
                    "Kyber",
                    "BCPQC"
            );
        }else if(clientHelloCipherSuitesContainOneWithFrodoKEM()){
            clientPublicKeyFrodo = CryptographyModule.keys.byteArrToPublicKey(
                    keys[keys.length-1],
                    "Frodo",
                    "BCPQC"
            );
        }else if(clientHelloCipherSuitesContainOneWithKyberKEM()){
            clientPublicKeyKyber = CryptographyModule.keys.byteArrToPublicKey(
                    keys[keys.length-1],
                    "Kyber",
                    "BCPQC"
            );
        }
    }

    private KeyShareExtension getKeyShareExtensionFromClientHello() throws Exception {
        PQTLSExtension[] extensions = clientHelloMessage.getExtensions();
        for(PQTLSExtension extension : extensions){
            if(extension.getIdentifier() == Constants.EXTENSION_IDENTIFIER_KEY_SHARE){
                return (KeyShareExtension)extension;
            }
        }
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 90
        alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.missing_extension);
        throw new Exception("");
    }

    //TODO
    // will be rewritten with the use of a keystore
    private void setStateMachineKeyPairs() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        stateMachine.ecKeyPair = CryptographyModule.keys.generateECKeyPair(stateMachine.preferredCurveIdentifier);
        if(cipherSuiteUsesFrodoKEM()){
            stateMachine.frodoEncapsulatedSecret = CryptographyModule.keys.generateEncapsulatedSecret(
                    clientPublicKeyFrodo,
                    "Frodo",
                    getSymmetricCipherNameFromCipherSuite()
            );
        }
        if(cipherSuiteUsesKyberKEM()){
            stateMachine.kyberEncapsulatedSecret = CryptographyModule.keys.generateEncapsulatedSecret(
                    clientPublicKeyKyber,
                    "Kyber",
                    getSymmetricCipherNameFromCipherSuite()
            );
        }
    }

    private boolean cipherSuiteUsesKyberKEM() {
        return stateMachine.preferredCipherSuite.ordinal() >= 5 && stateMachine.preferredCipherSuite.ordinal() <= 8;
    }

    private boolean cipherSuiteUsesFrodoKEM() {
        return stateMachine.preferredCipherSuite.ordinal() < 5 || stateMachine.preferredCipherSuite.ordinal() > 8;
    }

    private boolean clientHelloCipherSuitesContainOneWithFrodoKEM(){
        for(CipherSuite cipherSuite: clientHelloMessage.getCipherSuites()){
            if(cipherSuite.ordinal() < 5 || cipherSuite.ordinal() > 8){
                return true;
            }
        }
        return false;
    }
    private boolean clientHelloCipherSuitesContainOneWithKyberKEM(){
        for(CipherSuite cipherSuite: clientHelloMessage.getCipherSuites()){
            if(cipherSuite.ordinal() >= 5 && cipherSuite.ordinal() <= 8){
                return true;
            }
        }
        return false;
    }
    private void setStateMachinePreferredCurve() throws Exception {
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
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 88
        alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.handshake_failure);
        throw new Exception("");
    }

    private CurveIdentifier[] getSupportedCurvesByClient() throws Exception {
        PQTLSExtension[] extensions = clientHelloMessage.getExtensions();
        for(PQTLSExtension extension : extensions){
            if(extension.getIdentifier() == Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS){
                return ((SupportedGroupsExtension)extension).getSupportedGroups();
            }
        }
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 90
        alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.missing_extension);
        throw new Exception("");
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
                if(stateMachine.supportedCipherSuites[i] == clientCipherSuites[j]){
                    //This if-statement will always be reached since there is a mandatory cipher suite
                    stateMachine.preferredCipherSuite = clientCipherSuites[j];
                    return;
                }
            }
        }
    }


    @Override
    public PQTLSMessage getMessage() {
        if(alertMessage == null){
            return new HelloMessage.HelloBuilder()
                    .extensions(new PQTLSExtension[]{keyShareExtension})
                    .cipherSuites(new CipherSuite[]{stateMachine.preferredCipherSuite})
                    .sessionID(stateMachine.sessionID)
                    .LegacyVersion(new byte[]{0x03, 0x03})
                    .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO)
                    .random(stateMachine.random)
                    .build();
        }else{
            return alertMessage;
        }
    }

    @Override
    public State next() {
        return new SendEncryptedExtensionsState();
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

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return true;
    }

}
