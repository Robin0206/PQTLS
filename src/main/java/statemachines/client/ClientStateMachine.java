package statemachines.client;

import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import crypto.enums.ECPointFormat;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import statemachines.FinishedState;
import statemachines.PQTLSStateMachine;

import java.security.*;
import java.util.ArrayList;

/*
Uses fluent builder pattern
The first state is always the ClientHelloState
 */
public class ClientStateMachine extends PQTLSStateMachine {

    protected boolean verifiedServerFinishedMessage;
    protected ArrayList<X509CertificateHolder> trustedCertificates;
    protected boolean certificatesTrusted;
    protected X509CertificateHolder certificateUsedByServer;
    protected String sigAlgUsedByServer;
    protected boolean signatureValid;
    protected ArrayList<PQTLSExtension> extensions;
    protected int chosenCurveKeyIndex;
    protected PQTLSMessage serverEncryptedExtensions;
    protected KeyPair[] ecKeyPairs;
    protected KeyPair frodoKey;
    protected KeyPair kyberKey;
    protected String symmetricAlgorithm;
    protected ECPointFormat[] ecPointFormats;
    protected int numberOfCurvesToSendByClientHello;
    protected byte[] extensionIdentifiers;



    private ClientStateMachine(ClientStateMachineBuilder builder){
        super();
        this.setSupportedCurves(builder.curveIdentifiers);
        this.setSupportedSignatureAlgorithms(builder.supportedSignatureAlgorithms);
        this.setSupportedCipherSuites(builder.cipherSuites);
        setCurrentState(new ClientHelloState());
        setMessages(new ArrayList<>());
        this.ecPointFormats = builder.ecPointFormats;
        this.numberOfCurvesToSendByClientHello = builder.numberOfCurvesSendByClientHello;
        this.extensionIdentifiers = builder.extensionIdentifiers;
        this.trustedCertificates = builder.trustedCertificates;
    }

    public PQTLSMessage step(PQTLSMessage previousMessage) throws Exception {
        getCurrentState().setStateMachine(this);
        getCurrentState().setPreviousMessage(previousMessage);
        if (isNotNullMessage(previousMessage)) {
            getMessages().add(previousMessage);
        }
        getCurrentState().calculate();
        PQTLSMessage result = getCurrentState().getMessage();
        if (isNotNullMessage(result)) {
            getMessages().add(result);
        }
        setStepWithoutWaiting(getCurrentState().stepWithoutWaitingForMessage());
        setCurrentState(getCurrentState().next());
        if(getCurrentState() instanceof FinishedState){
            this.setFinished(true);
        }
        return result;
    }

    public boolean getCertificatesTrusted() {
        return certificatesTrusted;
    }

    public boolean getSignatureVerified() {
        return signatureValid;
    }

    public void setEcKeyPairs(KeyPair[] ecKeyPairs) {
        this.ecKeyPairs = ecKeyPairs;
    }

    public boolean verifiedServerFinishedMessage() {
        return verifiedServerFinishedMessage;
    }

    public static class ClientStateMachineBuilder {
        private PQTLSCipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private ECPointFormat[] ecPointFormats;
        private ArrayList<X509CertificateHolder> trustedCertificates;
        private byte[] supportedSignatureAlgorithms;
        private int numberOfCurvesSendByClientHello;
        private byte[] extensionIdentifiers;

        private boolean cipherSuitesSet = false;
        private boolean curveIdentifiersSet = false;
        private boolean numberOfCurvesSendByClientHelloSet = false;
        private boolean extensionIdentifiersSet = false;
        private boolean trustedCertificatesSet = false;

        public ClientStateMachineBuilder cipherSuites(PQTLSCipherSuite[] cipherSuites) {
            if (cipherSuitesContainMandatoryCipherSuite(cipherSuites)) {
                this.cipherSuites = cipherSuites;
                cipherSuitesSet = true;
                setSupportedSignatureAlgorithms();
                return this;
            } else {
                throw new RuntimeException("Doesnt contain the mandatory Cipher-Suite: TLS_ECDHE_FRODOKEM_SPHINCS_WITH_CHACHA20_POLY1305_SHA384");
            }

        }

        private void setSupportedSignatureAlgorithms() {
            for(PQTLSCipherSuite cs : cipherSuites){
                if(cs.toString().contains("DILITHIUM")){
                    supportedSignatureAlgorithms = new byte[]{0,1};
                    return;
                }
            }
            supportedSignatureAlgorithms = new byte[]{0};
        }

        private boolean cipherSuitesContainMandatoryCipherSuite(PQTLSCipherSuite[] cipherSuites) {
            for (PQTLSCipherSuite cipherSuite : cipherSuites) {
                if (cipherSuite == Constants.MANDATORY_CIPHERSUITE) {
                    return true;
                }
            }
            return false;
        }

        public ClientStateMachineBuilder curveIdentifiers(CurveIdentifier[] curveIdentifiers) {
            if (curveIdentifiers.length < 1) {
                throw new IllegalArgumentException("curveIdentifiers.length must be bigger than 0");
            }
            this.curveIdentifiers = curveIdentifiers;
            curveIdentifiersSet = true;
            return this;
        }

        public ClientStateMachineBuilder ecPointFormats(ECPointFormat[] ecPointFormats) {
            this.ecPointFormats = ecPointFormats;
            return this;
        }

        public ClientStateMachineBuilder numberOfCurvesSendByClientHello(int numberOfCurvesSendByClientHello) {
            if (!curveIdentifiersSet) {
                throw new IllegalArgumentException("SupportedGroups must be set before");
            } else if (numberOfCurvesSendByClientHello > curveIdentifiers.length) {
                throw new IllegalArgumentException("NumberOfCurves must be <= curveIdentifiers.length");
            }
            this.numberOfCurvesSendByClientHello = numberOfCurvesSendByClientHello;
            numberOfCurvesSendByClientHelloSet = true;
            return this;
        }

        public ClientStateMachineBuilder trustedCertificates(ArrayList<X509CertificateHolder> trustedCertificates) {
            this.trustedCertificates = trustedCertificates;
            this.trustedCertificatesSet = true;
            return this;
        }

        public ClientStateMachineBuilder extensionIdentifiers(byte[] extensionIdentifiers) {
            this.extensionIdentifiers = extensionIdentifiers;
            extensionIdentifiersSet = true;
            return this;
        }

        public ClientStateMachine build() {
            if (!numberOfCurvesSendByClientHelloSet) {
                numberOfCurvesSendByClientHello = curveIdentifiers.length;
            }
            if (
                    cipherSuitesSet &&
                            curveIdentifiersSet &&
                            extensionIdentifiersSet &&
                            trustedCertificatesSet
            ) {
                return new ClientStateMachine(this);
            } else {
                throw new IllegalArgumentException("before calling build, the following builder methods must be called:\n" +
                        "cipherSuites, curveIdentifiers, extensionIdentifiers, supportedCertificates");
            }
        }
    }
}
