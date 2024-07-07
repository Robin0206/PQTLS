package statemachines.server;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import statemachines.State;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;


public class ServerStateMachine {

    protected CurveIdentifier[] supportedCurves;
    protected CurveIdentifier preferredCurveIdentifier;
    protected KeyPair ecKeyPair;
    protected SecretKeyWithEncapsulation frodoEncapsulatedSecret;
    protected SecretKeyWithEncapsulation kyberEncapsulatedSecret;
    protected CipherSuite preferredCipherSuite;
    protected CipherSuite[] supportedCipherSuites;
    private State currentState;
    protected byte[] sessionID;
    protected byte[] random;
    protected PQTLSExtension[] extensions;

    private ServerStateMachine(ServerStateMachineBuilder builder){
        this.supportedCurves = builder.supportedCurves;
        this.supportedCipherSuites = builder.supportedCipherSuites;
        this.currentState = new ServerHelloState(this);
    }
    public PQTLSMessage step(PQTLSMessage previousMessage) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        currentState.setPreviousMessage(previousMessage);
        currentState.calculate();
        PQTLSMessage result = currentState.getMessage();
        currentState = currentState.next();
        return result;
    }

    public static class ServerStateMachineBuilder{
        protected CipherSuite[] supportedCipherSuites;
        public CurveIdentifier[] supportedCurves;
        boolean supportedCipherSuitesSet = false;
        boolean supportedCurvesSet = false;
        public ServerStateMachineBuilder cipherSuites(CipherSuite[] cipherSuites){
            if(cipherSuitesContainMandatoryCipherSuite(cipherSuites)){
                supportedCipherSuites = cipherSuites;
                supportedCipherSuitesSet = true;
                return this;
            }else{
                throw new RuntimeException("Doesnt contain the mandatory Cipher-Suite: TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384");
            }
        }
        public ServerStateMachineBuilder supportedCurves(CurveIdentifier[] supportedCurves){
            if(supportedCurvesContainMandatoryCurve(supportedCurves)){
                this.supportedCurves = supportedCurves;
                supportedCurvesSet = true;
                return this;
            }else{
                throw new RuntimeException("Doesnt contain the mandatory CurveIdentifier: secp256r1");
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

        private boolean supportedCurvesContainMandatoryCurve(CurveIdentifier[] curveIdentifiers) {
            for(CurveIdentifier identifier : curveIdentifiers){
                if(identifier == CurveIdentifier.secp256r1){
                    return true;
                }
            }
            return false;
        }

        public ServerStateMachine build() throws Exception {
            throwExceptionIfNecessary();
            return new ServerStateMachine(this);
        }

        private void throwExceptionIfNecessary() throws Exception {
            if(!supportedCipherSuitesSet){
                throw new Exception("Cipher-Suites must be set before calling the build method");
            }
            if(!supportedCurvesSet){
                throw new Exception("Supported Curves must be set before calling the build method");
            }
        }
    }
}
