package statemachines.client.states;

import crypto.CryptographyModule;
import crypto.enums.CipherSuite;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.ECPointFormatsExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import messages.extensions.implementations.SupportedGroupsExtension;
import messages.implementations.HelloMessage;
import misc.Constants;
import statemachines.State;
import statemachines.client.ClientStateMachine;

import java.security.*;
import java.util.ArrayList;

public class ClientHelloState extends State {
    private final ClientStateMachine clientStateMachine;
    private KeyPair[] ecKeyPairs;
    private KeyPair frodoKey;
    private KeyPair kyberKey;
    private ArrayList<PQTLSExtension> extensions;

    public ClientHelloState(ClientStateMachine clientStateMachine){
        this.clientStateMachine = clientStateMachine;
    }


    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        calculateAndSetKeys();
        calculateExtensions();
    }

    private void calculateExtensions() {
        extensions = new ArrayList<>();
        byte [] extensionIdentifiers = clientStateMachine.getExtensionIdentifiers();
        for (byte extensionIdentifier : extensionIdentifiers) {
            extensions.add(generateExtension(extensionIdentifier));
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
        return new ECPointFormatsExtension(clientStateMachine.getECPointFormats());
    }

    private PQTLSExtension generateSignatureAlgorithmsExtension() {
        return new SignatureAlgorithmsExtension(clientStateMachine.getSignatureAlgorithms());
    }

    private PQTLSExtension generateSupportedGroupsExtension() {
        return new SupportedGroupsExtension(clientStateMachine.getSupportedGroups());
    }

    private PQTLSExtension generateKeyShareExtension() {
        int keysArrSize = clientStateMachine.getNumberOfECKeysToSend();
        if(cipherSuitesContainOneWithFrodoKEM()){
            keysArrSize++;
        }
        if(cipherSuitesContainOneWithKyberKEM()){
            keysArrSize++;
        }

        byte[][] keys = new byte[keysArrSize][];
        for (int i = 0; i < clientStateMachine.getNumberOfECKeysToSend(); i++) {
            keys[i] = ecKeyPairs[i].getPublic().getEncoded();
        }
        //if it uses frodoKem and kyber
        if(keysArrSize == clientStateMachine.getNumberOfECKeysToSend() + 2){
            keys[keys.length-2] = frodoKey.getPublic().getEncoded();
            keys[keys.length-1] = kyberKey.getPublic().getEncoded();
        }//if it uses frodoKem or kyber
        else if(keysArrSize == clientStateMachine.getNumberOfECKeysToSend() + 1){
            if(cipherSuitesContainOneWithFrodoKEM()){
                keys[keys.length-1] = frodoKey.getPublic().getEncoded();
            }else{
                keys[keys.length-1] = kyberKey.getPublic().getEncoded();
            }
        }


        return new KeyShareExtension(keys);
    }
    //TODO
    //  Will later use a keystore
    //sets them in this class and the clientHelloStateMachine
    private void calculateAndSetKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //calculate Keys
        this.ecKeyPairs = CryptographyModule.generateECKeyPairs(clientStateMachine.getSupportedGroups());
        this.frodoKey = CryptographyModule.generateFrodoKeyPair();
        this.kyberKey = CryptographyModule.generateKyberKeyPair();
        clientStateMachine.setEcKeyPairs(ecKeyPairs);
        if(cipherSuitesContainOneWithFrodoKEM()){
            clientStateMachine.setFrodoKey(frodoKey);
        }
        if(cipherSuitesContainOneWithKyberKEM()){
            clientStateMachine.setKyberKey(kyberKey);
        }
    }

    private boolean cipherSuitesContainOneWithKyberKEM() {
        for(CipherSuite cipherSuite : clientStateMachine.getCipherSuites()){
            if(cipherSuite.ordinal() >= 7 && cipherSuite.ordinal() <= 12){
                return true;
            }
        }
        return false;
    }

    private boolean cipherSuitesContainOneWithFrodoKEM() {
        for(CipherSuite cipherSuite : clientStateMachine.getCipherSuites()){
            if(cipherSuite.ordinal() < 7 || cipherSuite.ordinal() > 12){
                return true;
            }
        }
        return false;
    }

    @Override
    public PQTLSMessage getMessage() {
        SecureRandom random = new SecureRandom();
        PQTLSExtension[] extensionsArray = new PQTLSExtension[extensions.size()];
        for (int i = 0; i < extensionsArray.length; i++) {
            extensionsArray[i] = extensions.get(i);
        }
        byte[] sessionID = new byte[Constants.HELLO_MESSAGE_RANDOM_LENGTH];
        byte[] rand = new byte[Constants.HELLO_MESSAGE_RANDOM_LENGTH];
        random.nextBytes(sessionID);
        random.nextBytes(rand);
        return new HelloMessage.HelloBuilder()
                .extensions(extensionsArray)
                .cipherSuites(clientStateMachine.getCipherSuites())
                .sessionID(sessionID)
                .LegacyVersion(new byte[]{0x03, 0x03})
                .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO)
                .random(rand)
                .build();
    }

    @Override
    public State next() {
        return null;
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {}
}
