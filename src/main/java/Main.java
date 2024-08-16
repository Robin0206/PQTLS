
import crypto.CryptographyModule;
import crypto.enums.PQTLSCipherSuite;
import crypto.enums.CurveIdentifier;
import messages.PQTLSMessage;
import messages.implementations.HelloMessage;
import messages.implementations.NullMessage;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Vector;

public class Main {
    /*
    Main should show messages from a complete Handshake
     */
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        Security.addProvider(new BouncyCastleProvider());
        testProviderImports();
        KeyPair sphincsKeyPair = CryptographyModule.keys.generateSPHINCSKeyPair();
        KeyPair dilithiumKeyPair = CryptographyModule.keys.generateDilithiumKeyPair();
        X509CertificateHolder sphincsCertificate = CryptographyModule.certificate.generateSelfSignedTestCertificate(sphincsKeyPair, "SPHINCSPlus");
        X509CertificateHolder dilithiumCertificate = CryptographyModule.certificate.generateSelfSignedTestCertificate(dilithiumKeyPair, "Dilithium");
        ArrayList<X509CertificateHolder[]> serverCertificateChains = new ArrayList<>();
        serverCertificateChains.add(new X509CertificateHolder[]{sphincsCertificate});
        serverCertificateChains.add(new X509CertificateHolder[]{dilithiumCertificate});
        ArrayList<X509CertificateHolder> clientCertificates = new ArrayList<>();
        clientCertificates.add(sphincsCertificate);
        ClientStateMachine clientStateMachine = new ClientStateMachine.ClientStateMachineBuilder()
                .cipherSuites(new PQTLSCipherSuite[]{
                        PQTLSCipherSuite.TLS_ECDHE_KYBER_SPHINCS_WITH_CHACHA20_POLY1305_SHA256,
                        PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_KYBER_SPHINCS_WITH_CHACHA20_POLY1305_SHA256,
                        PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_KYBER_SPHINCS_WITH_AES_256_GCM_SHA384,
                        Constants.MANDATORY_CIPHERSUITE
                })
                .curveIdentifiers(new CurveIdentifier[]{
                        CurveIdentifier.secp384r1,
                        CurveIdentifier.secp256r1
                })
                .extensionIdentifiers(new byte[]{
                        Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS,
                        Constants.EXTENSION_IDENTIFIER_KEY_SHARE,
                        Constants.EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS
                })
                .trustedCertificates(clientCertificates)
                .numberOfCurvesSendByClientHello(2)
                .build();
        HelloMessage message1 =
                (HelloMessage) clientStateMachine.step(new NullMessage());

        System.out.println("Client Sends Client Hello:");
        message1.printVerbose();

        ServerStateMachine serverStateMachine = new ServerStateMachine.ServerStateMachineBuilder()
                .supportedCurves(new CurveIdentifier[]{
                        CurveIdentifier.secp384r1,
                        CurveIdentifier.secp256r1
                })
                .cipherSuites(new PQTLSCipherSuite[]{
                        Constants.MANDATORY_CIPHERSUITE,
                        PQTLSCipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                })
                .certificateChains(serverCertificateChains)
                .signatureKeyPairs(new KeyPair[]{sphincsKeyPair, dilithiumKeyPair})
                .build();
        HelloMessage message2 =
                (HelloMessage) serverStateMachine.step(message1);
        System.out.println();
        System.out.println("Server sends Server Hello");
        message2.printVerbose();
        clientStateMachine.step(message2);
        PQTLSMessage message3 = serverStateMachine.step(new NullMessage());
        System.out.println();
        System.out.println("Server sends Encrypted Extensions");
        message3.printVerbose();
        clientStateMachine.step(message3);

        PQTLSMessage message4 = serverStateMachine.step(new NullMessage());
        System.out.println();
        System.out.println("Server sends Server Certificate");
        message4.printVerbose();

        clientStateMachine.step(message4);
        System.out.println("Client trusted certificates: " +
                clientStateMachine.getCertificatesTrusted());

        PQTLSMessage message5 = serverStateMachine.step(new NullMessage());
        System.out.println();
        System.out.println("Server sends Server Certificate Verify");
        message5.printVerbose();
        clientStateMachine.step(message5);
        System.out.println("Client checked if signature is valid: " + clientStateMachine.getSignatureVerified());


        PQTLSMessage message6 = serverStateMachine.step(new NullMessage());
        System.out.println();
        System.out.println("Server sends Handshake finished");
        message6.printVerbose();

        PQTLSMessage message7 = clientStateMachine.step(message6);
        System.out.println();
        System.out.println("Client sends Handshake finished");
        message7.printVerbose();
        System.out.println("Client checked if ServerFinishedMessage is valid: " + clientStateMachine.verifiedServerFinishedMessage());

        serverStateMachine.step(message7);
        System.out.println("server checked if ClientFinishedMessage is valid: " + serverStateMachine.verifiedClientFinishedMessage());

    }

    private static void testProviderImports() {
        testStaticImportPQProvider();
        testStaticImportJCSSEProvider();
        testStaticImportCoreProvider();
    }

    private static void testStaticImportCoreProvider() {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
            System.out.println("Exception while testing static import of CoreProvider!");
            throw new RuntimeException(e);
        }
    }

    private static void testStaticImportPQProvider() {
        try {
            Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println("Exception while testing static import of PQCProvider!");
            throw new RuntimeException(e);
        }
    }

    private static void testStaticImportJCSSEProvider() {

        try {
            TlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
            InetAddress address = InetAddress.getByName("127.0.0.1");
            TlsClient client = new TlsClient() {
                @Override
                public void init(TlsClientContext tlsClientContext) {

                }

                @Override
                public TlsSession getSessionToResume() {
                    return null;
                }

                @Override
                public Vector getExternalPSKs() {
                    return null;
                }

                @Override
                public boolean isFallback() {
                    return false;
                }

                @Override
                public Hashtable getClientExtensions() {
                    return null;
                }

                @Override
                public Vector getEarlyKeyShareGroups() {
                    return null;
                }

                @Override
                public boolean shouldUseCompatibilityMode() {
                    return false;
                }

                @Override
                public void notifyServerVersion(ProtocolVersion protocolVersion) {

                }

                @Override
                public void notifySessionToResume(TlsSession tlsSession) {

                }

                @Override
                public void notifySessionID(byte[] bytes) {

                }

                @Override
                public void notifySelectedCipherSuite(int i) {

                }

                @Override
                public void notifySelectedPSK(TlsPSK tlsPSK) {

                }

                @Override
                public void processServerExtensions(Hashtable hashtable) {

                }

                @Override
                public void processServerSupplementalData(Vector vector) {

                }

                @Override
                public TlsPSKIdentity getPSKIdentity() {
                    return null;
                }

                @Override
                public TlsSRPIdentity getSRPIdentity() {
                    return null;
                }

                @Override
                public TlsDHGroupVerifier getDHGroupVerifier() {
                    return null;
                }

                @Override
                public TlsSRPConfigVerifier getSRPConfigVerifier() {
                    return null;
                }

                @Override
                public TlsAuthentication getAuthentication() {
                    return null;
                }

                @Override
                public Vector getClientSupplementalData() {
                    return null;
                }

                @Override
                public void notifyNewSessionTicket(NewSessionTicket newSessionTicket) {

                }

                @Override
                public TlsCrypto getCrypto() {
                    return null;
                }

                @Override
                public void notifyCloseHandle(TlsCloseable tlsCloseable) {

                }

                @Override
                public void cancel() {

                }

                @Override
                public ProtocolVersion[] getProtocolVersions() {
                    return new ProtocolVersion[0];
                }

                @Override
                public int[] getCipherSuites() {
                    return new int[0];
                }

                @Override
                public void notifyHandshakeBeginning() {

                }

                @Override
                public int getHandshakeTimeoutMillis() {
                    return 0;
                }

                @Override
                public int getHandshakeResendTimeMillis() {
                    return 0;
                }

                @Override
                public boolean allowLegacyResumption() {
                    return false;
                }

                @Override
                public int getMaxCertificateChainLength() {
                    return 0;
                }

                @Override
                public int getMaxHandshakeMessageSize() {
                    return 0;
                }

                @Override
                public short[] getPskKeyExchangeModes() {
                    return new short[0];
                }

                @Override
                public boolean requiresCloseNotify() {
                    return false;
                }

                @Override
                public boolean requiresExtendedMasterSecret() {
                    return false;
                }

                @Override
                public boolean shouldCheckSigAlgOfPeerCerts() {
                    return false;
                }

                @Override
                public boolean shouldUseExtendedMasterSecret() {
                    return false;
                }

                @Override
                public boolean shouldUseExtendedPadding() {
                    return false;
                }

                @Override
                public boolean shouldUseGMTUnixTime() {
                    return false;
                }

                @Override
                public void notifySecureRenegotiation(boolean b) {

                }

                @Override
                public TlsKeyExchangeFactory getKeyExchangeFactory() {
                    return null;
                }

                @Override
                public void notifyAlertRaised(short i, short i1, String s, Throwable throwable) {

                }

                @Override
                public void notifyAlertReceived(short i, short i1) {

                }

                @Override
                public void notifyConnectionClosed() {

                }

                @Override
                public void notifyHandshakeComplete() {

                }

                @Override
                public TlsHeartbeat getHeartbeat() {
                    return null;
                }

                @Override
                public short getHeartbeatPolicy() {
                    return 0;
                }

                @Override
                public int getRenegotiationPolicy() {
                    return 0;
                }
            };
        } catch (UnknownHostException e) {
            System.out.println("Exception while using static import of JSSEProvider!");
            throw new RuntimeException(e);
        }

    }
}
