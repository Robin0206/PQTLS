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
import org.bouncycastle.pqc.jcajce.provider.frodo.BCFrodoPublicKey;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import statemachines.State;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

public class ServerHelloState extends State {
    ServerStateMachine stateMachine;
    private HelloMessage clientHelloMessage;
    private PublicKey clientPublicKeyFrodo;
    private PublicKey clientPublicKeyKyber;
    private KeyShareExtension keyShareExtension;

    public ServerHelloState(ServerStateMachine stateMachine) {
        super();
        this.stateMachine = stateMachine;
    }

    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        setStateMachinePreferredCipherSuite();
        setStateMachinePreferredCurve();
        setStateMachineSessionID();
        setStateMachineRandom();
        extractPQKeyPairsFromClientHelloMessage();
        setStateMachineKeyPairs();
        generateKeyShareExtension();
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
        if(cipherSuiteUsesFrodoKEM()){
            clientPublicKeyFrodo = KeyFactory.getInstance("Frodo", "BCPQC")
                    .generatePublic(
                            new X509EncodedKeySpec(
                                    keys[keys.length-2]
                            )
                    )
            ;
        }
        if(cipherSuiteUsesKyberKEM()){
            clientPublicKeyKyber = KeyFactory.getInstance("Kyber", "BCPQC")
                    .generatePublic(
                            new X509EncodedKeySpec(
                                    keys[keys.length-1]
                            )
                    )
            ;
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
            stateMachine.frodoEncapsulatedSecret = CryptographyModule.generateEncapsulatedSecret(clientPublicKeyFrodo, "Frodo");
        }
        if(cipherSuiteUsesKyberKEM()){
            stateMachine.kyberEncapsulatedSecret = CryptographyModule.generateEncapsulatedSecret(clientPublicKeyKyber, "Kyber");
        }
    }

    private boolean cipherSuiteUsesKyberKEM() {
        return stateMachine.preferredCipherSuite.ordinal() != 0 && !cipherSuiteUsesFrodoKEM();
    }

    private boolean cipherSuiteUsesFrodoKEM() {
        return stateMachine.preferredCipherSuite.ordinal() < 7 || stateMachine.preferredCipherSuite.ordinal() > 12;
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
}
