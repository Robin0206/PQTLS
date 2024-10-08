package statemachines;

import crypto.CryptographyModule;
import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import statemachines.client.ClientStateMachine;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

class ClientStateMachineTest {
    static SecureRandom random;
    PQTLSStateMachine clientStateMachine;

    @BeforeAll
    public static void initialize() {
        random = new SecureRandom();
    }

    @Test
    void buildingShouldNotThrowAnyException() {
        assertAll(()->{
            for (int i = 0; i < 100; i++) {
                System.out.println("buildingShouldNotThrowAnyException: " + i + " of " + "100");
                assertDoesNotThrow(this::buildRandomClientStateMachine);
            }
        });
    }

    private void buildRandomClientStateMachine() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        ArrayList<X509CertificateHolder> certificate = new ArrayList<>();
        certificate.add(CryptographyModule.certificate.generateSelfSignedTestCertificate("SPHINCSPlus"));
        clientStateMachine = new ClientStateMachine.ClientStateMachineBuilder()
                .cipherSuites(generateRandomCipherSuites())
                .curveIdentifiers(generateRandomCurveIdentifiers())
                .trustedCertificates(certificate)
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
        ArrayList<PQTLSCipherSuite> buffer = new ArrayList<>();
        for (int i = 0; i < cipherSuiteGetsUsed.length; i++) {
            if(cipherSuiteGetsUsed[i]){
                buffer.add(PQTLSCipherSuite.values()[i]);
            }
        }
        PQTLSCipherSuite[] result = new PQTLSCipherSuite[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }

}