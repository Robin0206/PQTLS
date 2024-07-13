package statemachines.client;

import crypto.SharedSecret;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import crypto.enums.ECPointFormat;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import org.bouncycastle.cert.X509CertificateHolder;
import statemachines.State;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/*
Uses fluent builder pattern
The first state is always the ClientHelloState
 */
public class ClientStateMachine {

    public ArrayList<X509CertificateHolder[]> trustedCertificates;
    public boolean certificatesTrusted;
    protected ArrayList<PQTLSExtension> extensions;
    protected int chosenCurveKeyIndex;
    protected SharedSecret sharedSecret;
    protected PQTLSMessage serverEncryptedExtensions;
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
    protected ArrayList<PQTLSMessage> messages;

    private boolean stepWithoutWaiting;

    private ClientStateMachine(ClientStateMachineBuilder builder) {
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

    public PQTLSMessage step(PQTLSMessage previousMessage) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, CertificateException {
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
        stepWithoutWaiting = currentState.stepWithoutWaiting();
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

    public static class ClientStateMachineBuilder {
        private CipherSuite[] cipherSuites;
        private CurveIdentifier[] curveIdentifiers;
        private ECPointFormat[] ecPointFormats;
        private ArrayList<X509CertificateHolder[]> trustedCertificates;
        private byte[] supportedSignatureAlgorithms;
        private int numberOfCurvesSendByClientHello;
        private byte[] extensionIdentifiers;

        private boolean cipherSuitesSet = false;
        private boolean curveIdentifiersSet = false;
        private boolean supportedSignatureAlgorithmsSet = false;
        private boolean numberOfCurvesSendByClientHelloSet = false;
        private boolean extensionIdentifiersSet = false;
        private boolean trustedCertificatesSet = false;

        public ClientStateMachineBuilder cipherSuites(CipherSuite[] cipherSuites) {
            if (cipherSuitesContainMandatoryCipherSuite(cipherSuites)) {
                this.cipherSuites = cipherSuites;
                cipherSuitesSet = true;
                return this;
            } else {
                throw new RuntimeException("Doesnt contain the mandatory Cipher-Suite: TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384");
            }

        }

        private boolean cipherSuitesContainMandatoryCipherSuite(CipherSuite[] cipherSuites) {
            for (CipherSuite cipherSuite : cipherSuites) {
                if (cipherSuite == CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384) {
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

        public ClientStateMachineBuilder supportedSignatureAlgorithms(byte[] supportedSignatureAlgorithms) {
            this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
            supportedSignatureAlgorithmsSet = true;
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

        public ClientStateMachineBuilder trustedCertificates(ArrayList<X509CertificateHolder[]> trustedCertificates) {
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
                            supportedSignatureAlgorithmsSet &&
                            extensionIdentifiersSet &&
                            trustedCertificatesSet
            ) {
                return new ClientStateMachine(this);
            } else {
                throw new IllegalArgumentException("before calling build, the following builder methods must be called:\n" +
                        "cipherSuites, curveIdentifiers, supportedSignatureAlgorithms, extensionIdentifiers, supportedCertificates");
            }
        }
    }
}
