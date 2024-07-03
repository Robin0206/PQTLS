package statemachines.client;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import crypto.enums.ECPointFormat;
import messages.PQTLSMessage;
import statemachines.State;
import statemachines.client.states.ClientHelloState;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
/*
Uses fluent builder pattern
The first state is always the ClientHelloState
 */
public class ClientStateMachine{

    private KeyPair[] ecKeyPairs;
    private KeyPair frodoKey;
    private KeyPair kyberKey;
    private State currentState;
    private CipherSuite[] cipherSuites;
    private CurveIdentifier[] curveIdentifiers;
    private ECPointFormat[] ecPointFormats;
    private byte[] supportedSignatureAlgorithms;
    private int numberOfCurvesToSendByClientHello;
    private byte[] extensionIdentifiers;

    private ClientStateMachine(ClientStateMachineBuilder builder){
        this.cipherSuites = builder.cipherSuites;
        this.curveIdentifiers = builder.curveIdentifiers;
        this.ecPointFormats = builder.ecPointFormats;
        this.supportedSignatureAlgorithms = builder.supportedSignatureAlgorithms;
        this.numberOfCurvesToSendByClientHello = builder.numberOfCurvesSendByClientHello;
        this.extensionIdentifiers = builder.extensionIdentifiers;
        currentState = new ClientHelloState(this);
    }

    public PQTLSMessage step() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        currentState.calculate();
        return currentState.getMessage();
    }

    public void nextState(PQTLSMessage message){
        currentState = currentState.next(message);
    }

    public CurveIdentifier[] getSupportedGroups() {
        return curveIdentifiers;
    }

    public void setEcKeyPairs(KeyPair[] ecKeyPairs) {
        this.ecKeyPairs = ecKeyPairs;
    }

    public void setFrodoKey(KeyPair frodoKey) {
        this.frodoKey = frodoKey;
    }

    public void setKyberKey(KeyPair kyberKey) {
        this.kyberKey = kyberKey;
    }

    public byte[] getExtensionIdentifiers() {
        return extensionIdentifiers;
    }

    public ECPointFormat[] getECPointFormats() {
        return ecPointFormats;
    }

    public byte[] getSignatureAlgorithms() {
        return supportedSignatureAlgorithms;
    }

    public CipherSuite[] getCipherSuites() {
        return cipherSuites;
    }

    public int getNumberOfECKeysToSend() {
        return this.numberOfCurvesToSendByClientHello;
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
        private boolean ecPointFormatsSet = false;
        private boolean supportedSignatureAlgorithmsSet = false;
        private boolean numberOfCurvesSendByClientHelloSet = false;
        private boolean extensionIdentifiersSet = false;

        public ClientStateMachineBuilder cipherSuites(CipherSuite[] cipherSuites){
            this.cipherSuites = cipherSuites;
            cipherSuitesSet = true;
            return this;
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
            ecPointFormatsSet = true;
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
