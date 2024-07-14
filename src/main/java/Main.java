
import crypto.CryptographyModule;
import crypto.enums.CipherSuite;
import crypto.enums.CurveIdentifier;
import crypto.enums.ECPointFormat;
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
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Vector;

public class Main {
    /*
    Main shouldnt throw any exception and print a Client-Hello-Message with the corresponding Server-Hello-Message
    as well as the shared secrets from the client and server state machine
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
        ArrayList<X509CertificateHolder[]> certificateChains = new ArrayList<>();
        certificateChains.add(new X509CertificateHolder[]{sphincsCertificate});
        certificateChains.add(new X509CertificateHolder[]{dilithiumCertificate});
        ArrayList<X509CertificateHolder[]> clientCertificateChains = new ArrayList<>();
        clientCertificateChains.add(new X509CertificateHolder[]{sphincsCertificate});
        ClientStateMachine clientStateMachine = new ClientStateMachine.ClientStateMachineBuilder()
                .cipherSuites(new CipherSuite[]{
                        CipherSuite.TLS_ECDHE_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384
                })
                .curveIdentifiers(new CurveIdentifier[]{
                        CurveIdentifier.secp384r1,
                        CurveIdentifier.secp256r1
                })
                .ecPointFormats(new ECPointFormat[]{
                        ECPointFormat.ansiX962_compressed_char2,
                        ECPointFormat.uncompressed
                })
                .supportedSignatureAlgorithms(new byte[]{
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM,
                        Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS
                })
                .extensionIdentifiers(new byte[]{
                        Constants.EXTENSION_IDENTIFIER_EC_POINT_FORMATS,
                        Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS,
                        Constants.EXTENSION_IDENTIFIER_KEY_SHARE,
                        Constants.EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS
                })
                .trustedCertificates(certificateChains)
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
                .cipherSuites(new CipherSuite[]{
                        CipherSuite.TLS_ECDHE_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384
                })
                .certificateChains(certificateChains)
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
        /*
        PQTLSMessage message6 = serverStateMachine.step(new NullMessage());
        System.out.println();
        System.out.println("Server sends Handshake finished");
        message6.printVerbose();
        clientStateMachine.step(message6);
        */
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
                public Hashtable getClientExtensions() throws IOException {
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
                public void notifyServerVersion(ProtocolVersion protocolVersion) throws IOException {

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
                public void notifySelectedPSK(TlsPSK tlsPSK) throws IOException {

                }

                @Override
                public void processServerExtensions(Hashtable hashtable) throws IOException {

                }

                @Override
                public void processServerSupplementalData(Vector vector) throws IOException {

                }

                @Override
                public TlsPSKIdentity getPSKIdentity() throws IOException {
                    return null;
                }

                @Override
                public TlsSRPIdentity getSRPIdentity() throws IOException {
                    return null;
                }

                @Override
                public TlsDHGroupVerifier getDHGroupVerifier() throws IOException {
                    return null;
                }

                @Override
                public TlsSRPConfigVerifier getSRPConfigVerifier() throws IOException {
                    return null;
                }

                @Override
                public TlsAuthentication getAuthentication() throws IOException {
                    return null;
                }

                @Override
                public Vector getClientSupplementalData() throws IOException {
                    return null;
                }

                @Override
                public void notifyNewSessionTicket(NewSessionTicket newSessionTicket) throws IOException {

                }

                @Override
                public TlsCrypto getCrypto() {
                    return null;
                }

                @Override
                public void notifyCloseHandle(TlsCloseable tlsCloseable) {

                }

                @Override
                public void cancel() throws IOException {

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
                public void notifyHandshakeBeginning() throws IOException {

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
                public void notifySecureRenegotiation(boolean b) throws IOException {

                }

                @Override
                public TlsKeyExchangeFactory getKeyExchangeFactory() throws IOException {
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
                public void notifyHandshakeComplete() throws IOException {

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
