package statemachines.client;

import crypto.CryptographyModule;
import crypto.SharedSecret;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import crypto.enums.ECPointFormat;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import statemachines.State;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

/*
Uses fluent builder pattern
The first state is always the ClientHelloState
 */
public class ClientStateMachine {

    protected boolean verifiedServerFinishedMessage;
    protected ArrayList<X509CertificateHolder> trustedCertificates;
    protected boolean certificatesTrusted;
    protected X509CertificateHolder certificateUsedByServer;
    protected String sigAlgUsedByServer;
    protected boolean signatureValid;
    protected ArrayList<PQTLSExtension> extensions;
    protected int chosenCurveKeyIndex;
    protected PQTLSMessage serverEncryptedExtensions;
    protected CipherSuite chosenCipherSuite;
    protected SharedSecret sharedSecret;
    protected KeyPair[] ecKeyPairs;
    protected KeyPair frodoKey;
    protected KeyPair kyberKey;
    protected String symmetricAlgorithm;
    protected State currentState;
    protected CipherSuite[] cipherSuites;
    protected CurveIdentifier[] curveIdentifiers;
    protected CurveIdentifier chosenCurve;
    protected ECPointFormat[] ecPointFormats;
    protected byte[] supportedSignatureAlgorithms;
    protected int numberOfCurvesToSendByClientHello;
    protected byte[] extensionIdentifiers;
    protected ArrayList<PQTLSMessage> messages;

    private boolean stepWithoutWaiting;
    protected boolean finished = false;

    private ClientStateMachine(ClientStateMachineBuilder builder){
        messages = new ArrayList<>();
        this.cipherSuites = builder.cipherSuites;
        this.curveIdentifiers = builder.curveIdentifiers;
        this.ecPointFormats = builder.ecPointFormats;
        this.supportedSignatureAlgorithms = builder.supportedSignatureAlgorithms;
        this.numberOfCurvesToSendByClientHello = builder.numberOfCurvesSendByClientHello;
        this.extensionIdentifiers = builder.extensionIdentifiers;
        this.trustedCertificates = builder.trustedCertificates;
        currentState = new ClientHelloState();
    }

    public PQTLSMessage step(PQTLSMessage previousMessage) throws Exception {
        currentState.setStateMachine(this);
        currentState.setPreviousMessage(previousMessage);
        if (isNotNullMessage(previousMessage)) {
            messages.add(previousMessage);
        }
        currentState.calculate();
        PQTLSMessage result = currentState.getMessage();
        if (isNotNullMessage(result)) {
            messages.add(result);
        }
        stepWithoutWaiting = currentState.stepWithoutWaitingForMessage();
        currentState = currentState.next();
        return result;
    }

    private boolean isNotNullMessage(PQTLSMessage message) {
        return message.getBytes()[0] != (byte) 0xff;
    }

    public CurveIdentifier[] getSupportedGroups() {
        return curveIdentifiers;
    }

    public void setEcKeyPairs(KeyPair[] ecKeyPairs) {
        this.ecKeyPairs = ecKeyPairs;
    }

    public SharedSecret getSharedSecret() {
        return sharedSecret;
    }

    public boolean getCertificatesTrusted() {
        return certificatesTrusted;
    }

    public boolean getSignatureVerified() {
        return signatureValid;
    }

    public ArrayList<PQTLSMessage> getMessages() {
        return messages;
    }

    public boolean verifiedServerFinishedMessage() {
        return verifiedServerFinishedMessage;
    }

    public boolean stepWithoutWaiting() {
        return this.stepWithoutWaiting;
    }

    public boolean finished() {
        return this.finished;
    }

    public static class ClientStateMachineBuilder {
        private CipherSuite[] cipherSuites;
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

        public ClientStateMachineBuilder cipherSuites(CipherSuite[] cipherSuites) {
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
            for(CipherSuite cs : cipherSuites){
                if(cs.toString().contains("DILITHIUM")){
                    supportedSignatureAlgorithms = new byte[]{0,1};
                    return;
                }
            }
            supportedSignatureAlgorithms = new byte[]{0};
        }

        private boolean cipherSuitesContainMandatoryCipherSuite(CipherSuite[] cipherSuites) {
            for (CipherSuite cipherSuite : cipherSuites) {
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
