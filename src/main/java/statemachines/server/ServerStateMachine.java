package statemachines.server;

import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import misc.ByteUtils;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import statemachines.FinishedState;
import statemachines.PQTLSStateMachine;

import java.io.IOException;
import java.security.*;
import java.util.*;


public class ServerStateMachine extends PQTLSStateMachine {

    protected String sigAlgUsedInCertificate;
    protected PublicKey publicKeyUsedInCertificate;
    protected ArrayList<X509CertificateHolder[]> certificateChains;
    protected KeyPair[] signatureKeyPairs;
    protected KeyPair ecKeyPair;
    protected SecretKeyWithEncapsulation frodoEncapsulatedSecret;
    protected SecretKeyWithEncapsulation kyberEncapsulatedSecret;
    protected byte[] sessionID;
    protected byte[] random;
    protected PQTLSExtension[] extensions;
    protected boolean verifiedClientFinished;

    private ServerStateMachine(ServerStateMachineBuilder builder) {
        setMessages(new ArrayList<>());
        this.setSupportedCurves(builder.supportedCurves);
        this.setSupportedCipherSuites(builder.supportedCipherSuites);
        this.setCurrentState(new ServerHelloState());
        this.certificateChains = builder.certificateChains;
        this.setSupportedSignatureAlgorithms(builder.supportedSignatureAlgorithms);
        this.signatureKeyPairs = builder.signatureKeyPairs;
        setStepWithoutWaiting(false);
    }

    public PQTLSMessage step(PQTLSMessage previousMessage) throws Exception {
        getCurrentState().setStateMachine(this);
        getCurrentState().setPreviousMessage(previousMessage);
        if (isNotNullMessage(previousMessage)) {
            getMessages().add(previousMessage);
        }
        getCurrentState().calculate();
        PQTLSMessage result = getCurrentState().getMessage();
        if (result != null && isNotNullMessage(result)) {
            getMessages().add(result);
        }
        setStepWithoutWaiting(getCurrentState().stepWithoutWaitingForMessage());
        setCurrentState(getCurrentState().next());
        if (getCurrentState() instanceof FinishedState) {
            this.setFinished(true);
        }
        return result;
    }

    public String getPreferredSymmetricAlgorithm() {
        String[] splitCipherSuite = getChosenCipherSuite().toString().split("_");
        for (int i = 0; i < splitCipherSuite.length; i++) {
            if (Objects.equals(splitCipherSuite[i], "WITH")) {
                return splitCipherSuite[i + 1];
            }
        }
        throw new RuntimeException("Cant extract symmetric algorithm from cipher suite!");
    }

    public boolean verifiedClientFinishedMessage() {
        return verifiedClientFinished;
    }

    public static class ServerStateMachineBuilder {
        KeyPair[] signatureKeyPairs;
        protected PQTLSCipherSuite[] supportedCipherSuites;
        public CurveIdentifier[] supportedCurves;
        boolean supportedCipherSuitesSet = false;
        boolean supportedCurvesSet = false;
        ArrayList<X509CertificateHolder[]> certificateChains;
        private boolean certificatesSet = false;
        private boolean signatureKeyPairsSet = false;
        byte[] supportedSignatureAlgorithms;

        public ServerStateMachineBuilder cipherSuites(PQTLSCipherSuite[] cipherSuites) {
            if (cipherSuitesContainMandatoryCipherSuite(cipherSuites)) {
                supportedCipherSuites = cipherSuites;
                supportedCipherSuitesSet = true;
                return this;
            } else {
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
            for (X509CertificateHolder[] certificateChain : certificateChains) {
                for (X509CertificateHolder certificate : certificateChain) {
                    switch (certificate.getSignatureAlgorithm().getAlgorithm().getId()) {
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

        public ServerStateMachineBuilder supportedCurves(CurveIdentifier[] supportedCurves) {
            if (supportedCurvesContainMandatoryCurve(supportedCurves)) {
                this.supportedCurves = supportedCurves;
                supportedCurvesSet = true;
                return this;
            } else {
                throw new RuntimeException("Doesnt contain the mandatory CurveIdentifier: secp256r1");
            }
        }

        public ServerStateMachineBuilder signatureKeyPairs(KeyPair[] signatureKeyPairs) {
            this.signatureKeyPairs = signatureKeyPairs;
            this.signatureKeyPairsSet = true;
            return this;
        }

        private boolean cipherSuitesContainMandatoryCipherSuite(PQTLSCipherSuite[] cipherSuites) {
            for (PQTLSCipherSuite cipherSuite : cipherSuites) {
                if (cipherSuite == Constants.MANDATORY_CIPHERSUITE) {
                    return true;
                }
            }
            return false;
        }

        private boolean supportedCurvesContainMandatoryCurve(CurveIdentifier[] curveIdentifiers) {
            for (CurveIdentifier identifier : curveIdentifiers) {
                if (identifier == CurveIdentifier.secp256r1) {
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
            if (!supportedCipherSuitesSet) {
                throw new Exception("Cipher-Suites must be set before calling the build method");
            }
            if (!supportedCurvesSet) {
                throw new Exception("Supported Curves must be set before calling the build method");
            }
            if (!certificatesSet) {
                throw new Exception("Certificates must be set before calling the build method");
            }
            if (!signatureKeyPairsSet) {
                throw new Exception("Signature Key Pairs must be set before calling the build method");
            }
        }
    }
}
