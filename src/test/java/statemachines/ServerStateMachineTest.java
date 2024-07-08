package statemachines;

import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import statemachines.server.ServerStateMachine;

import java.security.SecureRandom;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

class ServerStateMachineTest {
    static SecureRandom random;
    ServerStateMachine serverStateMachine;

    @BeforeAll
    public static void initialize() {
        random = new SecureRandom();
    }

    @Test
    void buildingShouldNotThrowAnyException() {
        assertAll(()->{
            for (int i = 0; i < 1000; i++) {
                assertDoesNotThrow(this::buildRandomServerStateMachine);
            }
        });
    }

    private ServerStateMachine buildRandomServerStateMachine() throws Exception {
       return new ServerStateMachine.ServerStateMachineBuilder()
                .cipherSuites(generateRandomCipherSuites())
                .supportedCurves(generateRandomCurveIdentifiers())
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

    private CipherSuite[] generateRandomCipherSuites() {
        boolean[] cipherSuiteGetsUsed = new boolean[CipherSuite.values().length];
        for (int i = 0; i < cipherSuiteGetsUsed.length; i++) {
            cipherSuiteGetsUsed[i] = random.nextBoolean();
        }
        cipherSuiteGetsUsed[1] = true;
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
}