package statemachines;

import crypto.CryptographyModule;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import java.security.SecureRandom;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

public class StatemachineInteractionTest {
    ClientStateMachine clientStateMachine;
    ServerStateMachine serverStateMachine;
    static SecureRandom random;

    @BeforeAll
    public static void initialize() {
        random = new SecureRandom();
    }

    @Test
    void randomMachinesInteractingShouldNotThrow(){;
        assertDoesNotThrow(()->{
            for (int i = 0; i < 100; i++) {
                clientStateMachine = buildRandomClientStateMachine();
                serverStateMachine = buildRandomServerStateMachine();
                PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
                PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
                clientStateMachine.step(serverHelloMessage);
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
        return new ClientStateMachine.ClientStateMachineBuilder()
                .cipherSuites(generateRandomCipherSuites())
                .curveIdentifiers(generateRandomCurveIdentifiers())
                .supportedSignatureAlgorithms(generateRandomSupportedSignatureAlgorithms())
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

    private CipherSuite[] generateRandomCipherSuites() {
        boolean[] cipherSuiteGetsUsed = new boolean[CipherSuite.values().length];
        for (int i = 0; i < cipherSuiteGetsUsed.length; i++) {
            cipherSuiteGetsUsed[i] = random.nextBoolean();
        }
        cipherSuiteGetsUsed[1] = true;
        cipherSuiteGetsUsed[0] = false;
        ArrayList<CipherSuite> buffer = new ArrayList<>();
        for (int i = 0; i < cipherSuiteGetsUsed.length; i++) {
            if(cipherSuiteGetsUsed[i]){
                buffer.add(CipherSuite.values()[i]);
            }
        }
        if(buffer.isEmpty()){
            buffer.add(CipherSuite.TLS_ECDHE_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384);
        }
        CipherSuite[] result = new CipherSuite[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }

    private ServerStateMachine buildRandomServerStateMachine() throws Exception {
        ArrayList<X509CertificateHolder[]> certificateChains = new ArrayList<>();
        certificateChains.add(new X509CertificateHolder[]{CryptographyModule.certificate.generateSelfSignedTestCertificate("Dilithium")});
        return new ServerStateMachine.ServerStateMachineBuilder()
                .cipherSuites(generateRandomCipherSuites())
                .supportedCurves(generateRandomCurveIdentifiers())
                .certificateChains(certificateChains)
                .build();
    }
}
