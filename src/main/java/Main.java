import crypto.CipherSuite;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.implementations.HelloMessage;
import misc.Constants;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Hashtable;
import java.util.Vector;

public class Main {
    public static void main(String[]args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        Security.addProvider(new BouncyCastleProvider());
        //testProviderImports();


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("curve25519");
        kpg.initialize(ecGenParameterSpec);
        ECPublicKey key = (ECPublicKey) kpg.generateKeyPair().getPublic();
        byte[]frodoKey = new byte[168];
        new SecureRandom().nextBytes(frodoKey);
        byte[] ecKey = key.getEncoded();
        byte[] sessionID = new byte[32];
        KeyShareExtension keyShare = new KeyShareExtension(
                new byte[][]{ecKey, frodoKey},
                new byte[]{0x00, 0x1d}
        );
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        SignatureAlgorithmsExtension sig = new SignatureAlgorithmsExtension(new byte[]{0x00, 0x01});
        new SecureRandom().nextBytes(sessionID);
        HelloMessage message1 = new HelloMessage.HelloBuilder()
                .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO)
                .cipherSuites(new CipherSuite[]{
                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_FRODOKEM_FALCON_WITH_CHACHA20_256_POLY1305_SHA384
                })
                .random(random)
                .extensions(new PQTLSExtension[]{keyShare, sig})
                .protocolVersion((short)0x0301)
                .sessionID(sessionID)
                .build();
        message1.printVerbose();
        HelloMessage message2 = new HelloMessage.HelloBuilder().fromBytes(message1.getBytes()).build();
        message2.printVerbose();
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
        try{
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
