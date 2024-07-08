package statemachines.client;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import crypto.enums.ECPointFormat;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import statemachines.State;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/*
Uses fluent builder pattern
The first state is always the ClientHelloState
 */
public class ClientStateMachine{

    public ArrayList<PQTLSExtension> extensions;
    public int chosenCurveKeyIndex;
    protected CipherSuite chosenCipherSuite;
    protected KeyPair[] ecKeyPairs;
    protected KeyPair frodoKey;
    protected KeyPair kyberKey;
    protected State currentState;
    protected CipherSuite[] cipherSuites;
    protected CurveIdentifier[] curveIdentifiers;
    protected CurveIdentifier chosenCurve;
    protected ECPointFormat[] ecPointFormats;
    protected byte[] supportedSignatureAlgorithms;
    protected int numberOfCurvesToSendByClientHello;
    protected byte[] extensionIdentifiers;
    protected byte[] sharedSecret;
    protected ArrayList<PQTLSMessage> incomingMessages;

    private ClientStateMachine(ClientStateMachineBuilder builder){
        incomingMessages = new ArrayList<>();
        this.cipherSuites = builder.cipherSuites;
        this.curveIdentifiers = builder.curveIdentifiers;
        this.ecPointFormats = builder.ecPointFormats;
        this.supportedSignatureAlgorithms = builder.supportedSignatureAlgorithms;
        this.numberOfCurvesToSendByClientHello = builder.numberOfCurvesSendByClientHello;
        this.extensionIdentifiers = builder.extensionIdentifiers;
        currentState = new ClientHelloState();
    }

    public PQTLSMessage step(PQTLSMessage previousMessage) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        currentState.setStateMachine(this);
        currentState.setPreviousMessage(previousMessage);
        incomingMessages.add(previousMessage);
        currentState.calculate();
        PQTLSMessage result = currentState.getMessage();
        currentState = currentState.next();
        return result;
    }

    public CurveIdentifier[] getSupportedGroups() {
        return curveIdentifiers;
    }

    public void setEcKeyPairs(KeyPair[] ecKeyPairs) {
        this.ecKeyPairs = ecKeyPairs;
    }
    public byte[] getSharedSecret(){
        return sharedSecret;
    }
    public static class ClientStateMachineBuilder{
        private CipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private ECPointFormat[] ecPointFormats;
        private byte[] supportedSignatureAlgorithms;
        private int numberOfCurvesSendByClientHello;
        private byte[] extensionIdentifiers;

        private boolean cipherSuitesSet = false;
        private boolean curveIdentifiersSet = false;
        private boolean supportedSignatureAlgorithmsSet = false;
        private boolean numberOfCurvesSendByClientHelloSet = false;
        private boolean extensionIdentifiersSet = false;

        public ClientStateMachineBuilder cipherSuites(CipherSuite[] cipherSuites){
            if(cipherSuitesContainMandatoryCipherSuite(cipherSuites)){
                this.cipherSuites = cipherSuites;
                cipherSuitesSet = true;
                return this;
            }else{
                throw new RuntimeException("Doesnt contain the mandatory Cipher-Suite: TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384");
            }
            
        }

        private boolean cipherSuitesContainMandatoryCipherSuite(CipherSuite[] cipherSuites) {
            for(CipherSuite cipherSuite : cipherSuites){
                if(cipherSuite == CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384){
                    return true;
                }
            }
            return false;
        }

        public ClientStateMachineBuilder curveIdentifiers(CurveIdentifier[] curveIdentifiers){
            if(curveIdentifiers.length < 1){
                throw new IllegalArgumentException("curveIdentifiers.length must be bigger than 0");
            }
            this.curveIdentifiers = curveIdentifiers;
            curveIdentifiersSet = true;
            return this;
        }
        public ClientStateMachineBuilder ecPointFormats(ECPointFormat[] ecPointFormats){
            this.ecPointFormats = ecPointFormats;
            return this;
        }
        public ClientStateMachineBuilder supportedSignatureAlgorithms(byte[] supportedSignatureAlgorithms){
            this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
            supportedSignatureAlgorithmsSet = true;
            return this;
        }
        public ClientStateMachineBuilder numberOfCurvesSendByClientHello(int numberOfCurvesSendByClientHello){
            if(!curveIdentifiersSet){
                throw new IllegalArgumentException("SupportedGroups must be set before");
            }else if(numberOfCurvesSendByClientHello > curveIdentifiers.length){
                throw new IllegalArgumentException("NumberOfCurves must be <= curveIdentifiers.length");
            }
            this.numberOfCurvesSendByClientHello = numberOfCurvesSendByClientHello;
            numberOfCurvesSendByClientHelloSet = true;
            return this;
        }
        public ClientStateMachineBuilder extensionIdentifiers(byte[] extensionIdentifiers){
            this.extensionIdentifiers = extensionIdentifiers;
            extensionIdentifiersSet = true;
            return this;
        }
        public ClientStateMachine build(){
            if(!numberOfCurvesSendByClientHelloSet){
                numberOfCurvesSendByClientHello = curveIdentifiers.length;
            }
            if(
                    cipherSuitesSet &&
                    curveIdentifiersSet &&
                    supportedSignatureAlgorithmsSet &&
                    extensionIdentifiersSet
            ){
                return new ClientStateMachine(this);
            }else{
                throw new IllegalArgumentException("before calling build, the following builder methods must be called:\n" +
                        "cipherSuites, curveIdentifiers, supportedSignatureAlgorithms, extensionIdentifiers");
            }
        }
    }
}
