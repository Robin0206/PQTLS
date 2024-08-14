package statemachines.server;

import crypto.SharedSecretHolder;
import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import misc.ByteUtils;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import statemachines.FinishedState;
import statemachines.State;

import java.io.IOException;
import java.security.*;
import java.util.*;


public class ServerStateMachine {
    protected String sigAlgUsedInCertificate;
    protected PublicKey publicKeyUsedInCertificate;
    protected ArrayList<X509CertificateHolder[]> certificateChains;
    protected KeyPair[] signatureKeyPairs;
    byte[] supportedSignatureAlgorithms;
    protected SharedSecretHolder sharedSecretHolder;
    protected CurveIdentifier[] supportedCurves;
    protected CurveIdentifier preferredCurveIdentifier;
    protected KeyPair ecKeyPair;
    protected SecretKeyWithEncapsulation frodoEncapsulatedSecret;
    protected SecretKeyWithEncapsulation kyberEncapsulatedSecret;
    protected PQTLSCipherSuite preferredCipherSuite;
    protected PQTLSCipherSuite[] supportedCipherSuites;
    private State currentState;
    protected byte[] sessionID;
    protected byte[] random;
    protected PQTLSExtension[] extensions;
    protected ArrayList<PQTLSMessage> messages;
    private boolean stepWithoutWaiting;
    protected boolean verifiedClientFinished;
    boolean finished = false;

    private ServerStateMachine(ServerStateMachineBuilder builder){
        messages = new ArrayList<>();
        this.supportedCurves = builder.supportedCurves;
        this.supportedCipherSuites = builder.supportedCipherSuites;
        this.currentState = new ServerHelloState();
        this.certificateChains = builder.certificateChains;
        this.supportedSignatureAlgorithms = builder.supportedSignatureAlgorithms;
        this.signatureKeyPairs = builder.signatureKeyPairs;
        stepWithoutWaiting = false;
    }
    public PQTLSMessage step(PQTLSMessage previousMessage) throws Exception {
        currentState.setStateMachine(this);
        currentState.setPreviousMessage(previousMessage);
        if(isNotNullMessage(previousMessage)){
            messages.add(previousMessage);
        }
        currentState.calculate();
        PQTLSMessage result = currentState.getMessage();
        if(result != null && isNotNullMessage(result)){
            messages.add(result);
        }
        stepWithoutWaiting = currentState.stepWithoutWaitingForMessage();
        currentState = currentState.next();
        if(currentState instanceof FinishedState){
            this.finished = true;
        }
        return result;
    }

    private boolean isNotNullMessage(PQTLSMessage message) {
        return message.getBytes()[0] != (byte)0xff;
    }

    public SharedSecretHolder getSharedSecret(){
        return sharedSecretHolder;
    }

    public String getPreferredSymmetricAlgorithm() {
        String[] splitCipherSuite = preferredCipherSuite.toString().split("_");
        for (int i = 0; i < splitCipherSuite.length; i++) {
            if(Objects.equals(splitCipherSuite[i], "WITH")){
                return splitCipherSuite[i+1];
            }
        }
        throw new RuntimeException("Cant extract symmetric algorithm from cipher suite!");
    }

    public ArrayList<PQTLSMessage> getMessages() {
        return messages;
    }

    public boolean verifiedClientFinishedMessage() {
        return verifiedClientFinished;
    }

    public boolean stepWithoutWaitingForMessage() {
        return this.stepWithoutWaiting;
    }

    public boolean finished() {
        return this.finished;
    }

    public static class ServerStateMachineBuilder{
        KeyPair[] signatureKeyPairs;
        protected PQTLSCipherSuite[] supportedCipherSuites;
        public CurveIdentifier[] supportedCurves;
        boolean supportedCipherSuitesSet = false;
        boolean supportedCurvesSet = false;
        ArrayList<X509CertificateHolder[]> certificateChains;
        private boolean certificatesSet = false;
        private boolean signatureKeyPairsSet = false;
        byte[] supportedSignatureAlgorithms;

        public ServerStateMachineBuilder cipherSuites(PQTLSCipherSuite[] cipherSuites){
            if(cipherSuitesContainMandatoryCipherSuite(cipherSuites)){
                supportedCipherSuites = cipherSuites;
                supportedCipherSuitesSet = true;
                return this;
            }else{
                throw new RuntimeException("Doesnt contain the mandatory Cipher-Suite: TLS_ECDHE_FRODOKEM_SPHINCS_WITH_CHACHA20_POLY1305_SHA384");
            }
        }
        public ServerStateMachineBuilder certificateChains(ArrayList<X509CertificateHolder[]> certificateChains) throws IOException {
            this.certificateChains = certificateChains;
            setSupportedSignatureAlgorithms(certificateChains);
            this.certificatesSet = true;
            return this;
        }

        private void setSupportedSignatureAlgorithms(ArrayList<X509CertificateHolder[]> certificateChains) throws IOException {
            //dilithium 1.3.6.1.4.1.2.267.12.8.7
            //Sphincs 1.3.6.1.4.1.22554.2.5
            Set<Byte> supportedSignatureAlgorithmsBuffer = new HashSet<>();
            for(X509CertificateHolder[] certificateChain : certificateChains){
                for(X509CertificateHolder certificate : certificateChain){
                    switch (certificate.getSignatureAlgorithm().getAlgorithm().getId()){
                        case "1.3.6.1.4.1.2.267.12.8.7"://dilithium
                            supportedSignatureAlgorithmsBuffer.add((byte) 0x01);
                            break;
                        case "1.3.6.1.4.1.22554.2.5"://Sphincs
                            supportedSignatureAlgorithmsBuffer.add((byte) 0x00);
                            break;
                    }
                }
            }
            List<Byte> convertedSet = supportedSignatureAlgorithmsBuffer.stream().toList();
            supportedSignatureAlgorithms = ByteUtils.toByteArray(convertedSet);
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

        public ServerStateMachineBuilder signatureKeyPairs(KeyPair[] signatureKeyPairs){
            this.signatureKeyPairs = signatureKeyPairs;
            this.signatureKeyPairsSet = true;
            return  this;
        }
        private boolean cipherSuitesContainMandatoryCipherSuite(PQTLSCipherSuite[] cipherSuites) {
            for(PQTLSCipherSuite cipherSuite : cipherSuites){
                if(cipherSuite == Constants.MANDATORY_CIPHERSUITE){
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
            if(!certificatesSet){
                throw new Exception("Certificates must be set before calling the build method");
            }
            if(!signatureKeyPairsSet){
                throw new Exception("Signature Key Pairs must be set before calling the build method");
            }
        }
    }
}
