package statemachines;

import crypto.CryptographyModule;
import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import statemachines.server.ServerStateMachine;

import java.security.*;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

class ServerStateMachineTest {
    static SecureRandom random;
    ServerStateMachine serverStateMachine;
    static KeyPair sphincsKeyPair;
    static KeyPair dilithiumKeyPair;

    @BeforeAll
    public static void initialize() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        sphincsKeyPair = CryptographyModule.keys.generateSPHINCSKeyPair();
        dilithiumKeyPair = CryptographyModule.keys.generateDilithiumKeyPair();
        random = new SecureRandom();
    }

    @Test
    void buildingShouldNotThrowAnyException() {
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("buildingShouldNotThrowAnyException: " + i + " of " + "100");
                assertDoesNotThrow(this::buildRandomServerStateMachine);
            }
        });
    }

    private ServerStateMachine buildRandomServerStateMachine() throws Exception {
        ArrayList<X509CertificateHolder[]> certificateChains = new ArrayList<>();
        certificateChains.add(new X509CertificateHolder[]{CryptographyModule.certificate.generateSelfSignedTestCertificate(sphincsKeyPair,"SPHINCSPlus")});
        certificateChains.add(new X509CertificateHolder[]{CryptographyModule.certificate.generateSelfSignedTestCertificate(dilithiumKeyPair,"Dilithium")});
       return new ServerStateMachine.ServerStateMachineBuilder()
                .cipherSuites(generateRandomCipherSuites())
                .supportedCurves(generateRandomCurveIdentifiers())
               .certificateChains(certificateChains)
               .signatureKeyPairs(new KeyPair[]{dilithiumKeyPair, sphincsKeyPair})
                .build();
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
        ArrayList<PQTLSCipherSuite> buffer = new ArrayList<>();
        for (int i = 0; i < cipherSuiteGetsUsed.length; i++) {
            if(cipherSuiteGetsUsed[i]){
                buffer.add(PQTLSCipherSuite.values()[i]);
            }
        }
        if(buffer.isEmpty()){
            buffer.add(Constants.MANDATORY_CIPHERSUITE);
        }
        PQTLSCipherSuite[] result = new PQTLSCipherSuite[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }
}