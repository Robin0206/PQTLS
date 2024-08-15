import crypto.CryptographyModule;
import crypto.enums.CurveIdentifier;
import crypto.enums.PQTLSCipherSuite;
import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.tls.CipherSuite;
import statemachines.PQTLSStateMachine;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;

public class Benchmark {
    static SecureRandom random;
    static KeyPair sphincsKeyPair;
    static KeyPair dilithiumKeyPair;
    static X509CertificateHolder sphincsCert;
    static X509CertificateHolder dilithiumCert;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
        sphincsKeyPair = CryptographyModule.keys.generateSPHINCSKeyPair();
        sphincsCert = CryptographyModule.certificate.generateSelfSignedTestCertificate(sphincsKeyPair, "SPHINCSPlus");
        dilithiumKeyPair = CryptographyModule.keys.generateDilithiumKeyPair();
        dilithiumCert = CryptographyModule.certificate.generateSelfSignedTestCertificate(dilithiumKeyPair, "Dilithium");
        random = new SecureRandom();
        long[] handshakeTimes = new long[PQTLSCipherSuite.values().length-1];
        int[] handshakeBytes = new int[PQTLSCipherSuite.values().length-1];
        for (int i = 1; i < PQTLSCipherSuite.values().length; i++) {
            System.out.println("Benchmarking cipherSuite " + (i-1) + " of " + (PQTLSCipherSuite.values().length - 1));
            handshakeBytes[i-1] = benchmarkHandShakeBytes(PQTLSCipherSuite.values()[i]);
            handshakeTimes[i-1] = benchmarkHandShakeTime(PQTLSCipherSuite.values()[i]);
        }
        for (int i = 1; i < PQTLSCipherSuite.values().length; i++) {
            System.out.println(PQTLSCipherSuite.values()[i] + ": ");
            System.out.println("\t Time needed: " + handshakeTimes[i-1] + "ms");
            System.out.println("\t Bytes send: " + handshakeBytes[i-1]);
        }
    }

    public static long benchmarkHandShakeTime(PQTLSCipherSuite cipherSuite) throws Exception {
        PQTLSStateMachine clientStateMachine, serverStateMachine;
        clientStateMachine = buildClientStateMachine(cipherSuite);
        serverStateMachine = buildServerStateMachine(cipherSuite);
        long start, end;
        start = System.currentTimeMillis();
        PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
        PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
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
        end = System.currentTimeMillis();
        return (end - start);
    }

    public static int benchmarkHandShakeBytes(PQTLSCipherSuite cipherSuite) throws Exception {
        PQTLSStateMachine clientStateMachine, serverStateMachine;
        clientStateMachine = buildClientStateMachine(cipherSuite);
        serverStateMachine = buildServerStateMachine(cipherSuite);
        PQTLSMessage clientHelloMessage = clientStateMachine.step(new NullMessage());
        PQTLSMessage serverHelloMessage = serverStateMachine.step(clientHelloMessage);
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
        return
                        clientHelloMessage.getBytes().length +
                        serverHelloMessage.getBytes().length +
                        encryptedExtensionsMessage.getBytes().length +
                        certMessage.getBytes().length +
                        certVerifyMessage.getBytes().length +
                        clientHandshakeFinishedMessage.getBytes().length +
                        serverHandshakeFinishedMessage.getBytes().length;
    }

    private static PQTLSStateMachine buildServerStateMachine(PQTLSCipherSuite cipherSuite) throws Exception {
        PQTLSCipherSuite[] cipherSuites;
        ArrayList<X509CertificateHolder[]> certChains = new ArrayList<>();
        certChains.add(new X509CertificateHolder[]{sphincsCert});
        certChains.add(new X509CertificateHolder[]{dilithiumCert});
        if (cipherSuite == Constants.MANDATORY_CIPHERSUITE) {
            cipherSuites = new PQTLSCipherSuite[]{
                    Constants.MANDATORY_CIPHERSUITE
            };
        } else {
            cipherSuites = new PQTLSCipherSuite[]{
                    cipherSuite,
                    Constants.MANDATORY_CIPHERSUITE
            };
        }
        return new ServerStateMachine.ServerStateMachineBuilder()
                .supportedCurves(
                        new CurveIdentifier[]{
                                Constants.MANDATORY_CURVE
                        }
                )
                .signatureKeyPairs(new KeyPair[]{sphincsKeyPair, dilithiumKeyPair})
                .cipherSuites(cipherSuites)
                .certificateChains(certChains)
                .build();
    }

    private static PQTLSStateMachine buildClientStateMachine(PQTLSCipherSuite cipherSuite) {
        ArrayList<X509CertificateHolder> clientTrustedCerts = new ArrayList<>();
        clientTrustedCerts.add(sphincsCert);
        clientTrustedCerts.add(dilithiumCert);
        PQTLSCipherSuite[] cipherSuites;
        if (cipherSuite == Constants.MANDATORY_CIPHERSUITE) {
            cipherSuites = new PQTLSCipherSuite[]{
                    Constants.MANDATORY_CIPHERSUITE
            };
        } else {
            cipherSuites = new PQTLSCipherSuite[]{
                    cipherSuite,
                    Constants.MANDATORY_CIPHERSUITE
            };
        }
        return new ClientStateMachine.ClientStateMachineBuilder()
                .trustedCertificates(clientTrustedCerts)
                .curveIdentifiers(new CurveIdentifier[]{Constants.MANDATORY_CURVE})
                .numberOfCurvesSendByClientHello(1)
                .cipherSuites(cipherSuites)
                .extensionIdentifiers(
                        new byte[]{
                                Constants.EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS,
                                Constants.EXTENSION_IDENTIFIER_KEY_SHARE,
                                Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS
                        }
                )
                .build();
    }
}
