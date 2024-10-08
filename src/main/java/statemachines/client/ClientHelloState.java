package statemachines.client;

import crypto.CryptographyModule;
import crypto.enums.PQTLSCipherSuite;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.ECPointFormatsExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import messages.extensions.implementations.SupportedGroupsExtension;
import messages.implementations.HelloMessage;
import misc.Constants;
import statemachines.PQTLSStateMachine;
import statemachines.State;

import java.security.*;
import java.util.ArrayList;

/**
 * @author Robin Kroker
 * State responsible for building the client Hello Message
 * The next method returns the ClientCalcSharedSecretState
 */
public class ClientHelloState implements State {
    private ClientStateMachine stateMachine;

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        calculateAndSetKeys();
        calculateExtensions();
    }

    private void calculateExtensions() {
        stateMachine.extensions = new ArrayList<>();
        byte [] extensionIdentifiers = stateMachine.extensionIdentifiers;
        for (byte extensionIdentifier : extensionIdentifiers) {
            stateMachine.extensions.add(generateExtension(extensionIdentifier));
        }
    }

    private PQTLSExtension generateExtension(byte extensionIdentifier) {
        return switch (extensionIdentifier) {
            case Constants.EXTENSION_IDENTIFIER_KEY_SHARE -> generateKeyShareExtension();
            case Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS -> generateSupportedGroupsExtension();
            case Constants.EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS -> generateSignatureAlgorithmsExtension();
            case Constants.EXTENSION_IDENTIFIER_EC_POINT_FORMATS -> generateECPointFormatsExtension();
            default -> throw new IllegalArgumentException("Invalid identifier: " + extensionIdentifier);
        };
    }

    private PQTLSExtension generateECPointFormatsExtension() {
        return new ECPointFormatsExtension(stateMachine.ecPointFormats);
    }

    private PQTLSExtension generateSignatureAlgorithmsExtension() {
        return new SignatureAlgorithmsExtension(stateMachine.getSupportedSignatureAlgorithms());
    }

    private PQTLSExtension generateSupportedGroupsExtension() {
        return new SupportedGroupsExtension(stateMachine.getSupportedCurves());
    }

    private PQTLSExtension generateKeyShareExtension() {
        int keysArrSize = stateMachine.numberOfCurvesToSendByClientHello;
        if(cipherSuitesContainOneWithFrodoKEM()){
            keysArrSize++;
        }
        if(cipherSuitesContainOneWithKyberKEM()){
            keysArrSize++;
        }

        byte[][] keys = new byte[keysArrSize][];
        for (int i = 0; i < stateMachine.numberOfCurvesToSendByClientHello; i++) {
            keys[i] = stateMachine.ecKeyPairs[i].getPublic().getEncoded();
        }
        //if it uses frodoKem and kyber
        if(keysArrSize == stateMachine.numberOfCurvesToSendByClientHello + 2){
            keys[keys.length-2] = stateMachine.frodoKey.getPublic().getEncoded();
            keys[keys.length-1] = stateMachine.kyberKey.getPublic().getEncoded();
        }//if it uses frodoKem or kyber
        else if(keysArrSize == stateMachine.numberOfCurvesToSendByClientHello + 1){
            if(cipherSuitesContainOneWithFrodoKEM()){
                keys[keys.length-1] = stateMachine.frodoKey.getPublic().getEncoded();
            }else{
                keys[keys.length-1] = stateMachine.kyberKey.getPublic().getEncoded();
            }
        }
        return new KeyShareExtension(keys);
    }
    /**
     * sets the keys in this class and the clientHelloStateMachine
     */
    private void calculateAndSetKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //calculate Keys
        this.stateMachine.ecKeyPairs = CryptographyModule.keys.generateECKeyPairs(stateMachine.getSupportedCurves());
        this.stateMachine.frodoKey = CryptographyModule.keys.generateFrodoKeyPair();
        this.stateMachine.kyberKey = CryptographyModule.keys.generateKyberKeyPair();
        stateMachine.setEcKeyPairs(stateMachine.ecKeyPairs);
    }

    private boolean cipherSuitesContainOneWithKyberKEM() {
        for(PQTLSCipherSuite cipherSuite : stateMachine.getSupportedCipherSuites()){
            if(cipherSuite.ordinal() >= 5){
                return true;
            }
        }
        return false;
    }

    private boolean cipherSuitesContainOneWithFrodoKEM() {
        for(PQTLSCipherSuite cipherSuite : stateMachine.getSupportedCipherSuites()){
            if(cipherSuite.ordinal() < 5 || cipherSuite.ordinal() > 8){
                return true;
            }
        }
        return false;
    }

    @Override
    public PQTLSMessage getMessage() {
        SecureRandom random = new SecureRandom();
        PQTLSExtension[] extensionsArray = new PQTLSExtension[stateMachine.extensions.size()];
        for (int i = 0; i < extensionsArray.length; i++) {
            extensionsArray[i] = stateMachine.extensions.get(i);
        }
        byte[] sessionID = new byte[Constants.HELLO_MESSAGE_RANDOM_LENGTH];
        byte[] rand = new byte[Constants.HELLO_MESSAGE_RANDOM_LENGTH];
        random.nextBytes(sessionID);
        random.nextBytes(rand);
        return new HelloMessage.HelloBuilder()
                .extensions(extensionsArray)
                .cipherSuites(stateMachine.getSupportedCipherSuites())
                .sessionID(sessionID)
                .LegacyVersion(new byte[]{0x03, 0x03})
                .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO)
                .random(rand)
                .build();
    }

    @Override
    public State next() {
        return new ClientCalcSharedSecretState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {}

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
        this.stateMachine = (ClientStateMachine) stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }

}
