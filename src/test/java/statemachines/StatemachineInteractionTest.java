package statemachines;

import crypto.CryptographyModule;
import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import java.security.*;
import java.util.ArrayList;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

public class StatemachineInteractionTest {
    ClientStateMachine clientStateMachine;
    ServerStateMachine serverStateMachine;
    static SecureRandom random;
    static KeyPair sphincsKeyPair;
    static KeyPair dilithiumKeyPair;
    static X509CertificateHolder sphincsCert;
    static X509CertificateHolder dilithiumCert;

    @BeforeAll
    public static void initialize() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
        sphincsKeyPair = CryptographyModule.keys.generateSPHINCSKeyPair();
        sphincsCert = CryptographyModule.certificate.generateSelfSignedTestCertificate(sphincsKeyPair, "SPHINCSPlus");
        dilithiumKeyPair = CryptographyModule.keys.generateDilithiumKeyPair();
        dilithiumCert = CryptographyModule.certificate.generateSelfSignedTestCertificate(dilithiumKeyPair, "Dilithium");
        random = new SecureRandom();
    }

    @Test
    void randomMachinesInteractingShouldNotThrow(){
        assertDoesNotThrow(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("randomMachinesInteractingShouldNotThrowTest: " + i + " of " + "100");
                clientStateMachine = buildRandomClientStateMachine();
                serverStateMachine = buildRandomServerStateMachine();
                PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
                PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
                System.out.println("\t Cipher suite: " + serverStateMachine.getSharedSecret().getCipherSuite());
                clientStateMachine.step(serverHelloMessage);
                PQTLSMessage encryptedExtensionsMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(encryptedExtensionsMessage);
                PQTLSMessage certMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(certMessage);
                PQTLSMessage certVerifyMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(certVerifyMessage);
                PQTLSMessage serverHandshakeFinishedMessage = serverStateMachine.step(new NullMessage());
                PQTLSMessage clientHandshakeFinishedMessage = clientStateMachine.step(serverHandshakeFinishedMessage);
                serverStateMachine.step(clientHandshakeFinishedMessage);
            }
        });
    }

    @Test
    void randomMachinesInteractingCertTrustedTest(){
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("randomMachinesInteractingCertTrustedTest: " + i + " of " + "100");
                clientStateMachine = buildRandomClientStateMachine();
                serverStateMachine = buildRandomServerStateMachine();
                PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
                PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
                System.out.println("\t Cipher suite: " + serverStateMachine.getSharedSecret().getCipherSuite());
                clientStateMachine.step(serverHelloMessage);
                PQTLSMessage encryptedExtensionsMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(encryptedExtensionsMessage);
                PQTLSMessage certMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(certMessage);
                assertTrue(clientStateMachine.getCertificatesTrusted());
            }
        });
    }
    @Test
    void randomMachinesInteractingSigVerifiedTest(){
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("randomMachinesInteractingSigVerifiedTest: " + i + " of " + "100");
                clientStateMachine = buildRandomClientStateMachine();
                serverStateMachine = buildRandomServerStateMachine();
                PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
                PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
                System.out.println("\t Cipher suite: " + serverStateMachine.getSharedSecret().getCipherSuite());
                clientStateMachine.step(serverHelloMessage);
                PQTLSMessage encryptedExtensionsMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(encryptedExtensionsMessage);
                PQTLSMessage certMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(certMessage);
                PQTLSMessage sigVerifyMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(sigVerifyMessage);
                assertTrue(clientStateMachine.getSignatureVerified());
            }
        });
    }
    @Test
    void randomMachinesInteractingServerFinishMessagesVerifiedTest(){
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("randomMachinesInteractingServerFinishMessagesVerifiedTest: " + i + " of " + "100");
                clientStateMachine = buildRandomClientStateMachine();
                serverStateMachine = buildRandomServerStateMachine();
                PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
                PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
                System.out.println("\t Cipher suite: " + serverStateMachine.getSharedSecret().getCipherSuite());
                clientStateMachine.step(serverHelloMessage);
                PQTLSMessage encryptedExtensionsMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(encryptedExtensionsMessage);
                PQTLSMessage certMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(certMessage);
                PQTLSMessage certVerifyMessage = serverStateMachine.step(new NullMessage());
                clientStateMachine.step(certVerifyMessage);
                PQTLSMessage serverHandshakeFinishedMessage = serverStateMachine.step(new NullMessage());
                PQTLSMessage clientHandshakeFinishedMessage = clientStateMachine.step(serverHandshakeFinishedMessage);
                serverStateMachine.step(clientHandshakeFinishedMessage);
                assertTrue(serverStateMachine.verifiedClientFinishedMessage());
                assertTrue(clientStateMachine.verifiedServerFinishedMessage());
            }
        });
    }
    @Test
    void randomGeneratedMachinesShouldGenerateSameSharedSecretAfterInteracting(){
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                clientStateMachine = buildRandomClientStateMachine();
                serverStateMachine = buildRandomServerStateMachine();
                PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
                PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
                clientStateMachine.step(serverHelloMessage);
                assertTrue(clientStateMachine.getSharedSecret().equals(serverStateMachine.getSharedSecret()));
            }
        });
    }
    private ClientStateMachine buildRandomClientStateMachine() {
        ArrayList<X509CertificateHolder> certificates = new ArrayList<>();
        certificates.add(sphincsCert);
        certificates.add(dilithiumCert);
        return new ClientStateMachine.ClientStateMachineBuilder()
                .cipherSuites(generateRandomCipherSuites())
                .curveIdentifiers(generateRandomCurveIdentifiers())
                .trustedCertificates(certificates)
                .extensionIdentifiers(new byte[]{
                        Constants.EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS,
                        Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS,
                        Constants.EXTENSION_IDENTIFIER_KEY_SHARE
                }).build();
    }

    private byte[] generateRandomSupportedSignatureAlgorithms() {
        ArrayList<Byte> buffer = new ArrayList<>();
        if(random.nextBoolean()){
            buffer.add((byte) Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM);
        }

        if(random.nextBoolean()){
            buffer.add((byte) Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS);
        }
        if(buffer.isEmpty()){
            buffer.add((byte) Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS);
        }
        byte[] result = new byte[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }

    private CurveIdentifier[] generateRandomCurveIdentifiers() {
        boolean[] curveIdentifierGetsUsed = new boolean[CurveIdentifier.values().length];
        for (int i = 0; i < curveIdentifierGetsUsed.length; i++) {
            curveIdentifierGetsUsed[i] = random.nextBoolean();
        }
        curveIdentifierGetsUsed[0] = true;
        ArrayList<CurveIdentifier> buffer = new ArrayList<>();
        for (int i = 0; i < curveIdentifierGetsUsed.length; i++) {
            if(curveIdentifierGetsUsed[i]){
                buffer.add(CurveIdentifier.values()[i]);
            }
        }
        if(buffer.isEmpty()){
            buffer.add(CurveIdentifier.secp256r1);
        }
        CurveIdentifier[] result = new CurveIdentifier[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }

    private PQTLSCipherSuite[] generateRandomCipherSuites() {
        boolean[] cipherSuiteGetsUsed = new boolean[PQTLSCipherSuite.values().length];
        for (int i = 0; i < cipherSuiteGetsUsed.length; i++) {
            cipherSuiteGetsUsed[i] = random.nextBoolean();
        }
        cipherSuiteGetsUsed[Constants.MANDATORY_CIPHERSUITE.ordinal()] = true;
        cipherSuiteGetsUsed[0] = false;
        ArrayList<PQTLSCipherSuite> buffer = new ArrayList<>();
        for (int i = 0; i < cipherSuiteGetsUsed.length; i++) {
            if(cipherSuiteGetsUsed[i]){
                buffer.add(PQTLSCipherSuite.values()[i]);
            }
        }
        if(buffer.isEmpty()){
            buffer.add(PQTLSCipherSuite.TLS_ECDHE_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384);
        }
        Collections.shuffle(buffer);//This is needed because the used cipher suite is determined by the order they are in the servers CipherSuite[]
        PQTLSCipherSuite[] result = new PQTLSCipherSuite[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }

    private ServerStateMachine buildRandomServerStateMachine() throws Exception {
        ArrayList<X509CertificateHolder[]> certificateChains = new ArrayList<>();
        certificateChains.add(new X509CertificateHolder[]{sphincsCert});
        certificateChains.add(new X509CertificateHolder[]{dilithiumCert});
        return new ServerStateMachine.ServerStateMachineBuilder()
                .cipherSuites(generateRandomCipherSuites())
                .supportedCurves(generateRandomCurveIdentifiers())
                .certificateChains(certificateChains)
                .signatureKeyPairs(new KeyPair[]{sphincsKeyPair, dilithiumKeyPair})
                .build();
    }
}
