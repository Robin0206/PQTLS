package Server;


import misc.Constants;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;

public class ServerPSKConnection extends PSKTlsServer {

    private final String symmetricalAlgorithm;

    public ServerPSKConnection(TlsCrypto tlsCrypto, byte[] psk, String symmetricalAlgorithm) {
        super(tlsCrypto, new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() {
                return null;
            }

            @Override
            public byte[] getPSK(byte[] identity) {
                return psk;
            }
        });
        this.symmetricalAlgorithm = symmetricalAlgorithm;
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions() {
        return new ProtocolVersion[]{ProtocolVersion.TLSv13};
    }

    @Override
    protected int[] getSupportedCipherSuites() {
        if(symmetricalAlgorithm.toLowerCase() == "aes"){
            return new int[]{
                    CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384
            };
        }else{
            return new int[]{
                    CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
            };
        }
    }

    @Override
    public TlsSession getSessionToResume(byte[] sessionID) {
        return null;
    }
}
