package Server;


import crypto.SharedSecretHolder;
import misc.Constants;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;

public class ServerPSKConnection extends PSKTlsServer {

    private final SharedSecretHolder sharedSecretHolder;

    public ServerPSKConnection(TlsCrypto tlsCrypto, SharedSecretHolder sharedSecretHolder) {
        super(tlsCrypto, new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() {
                return null;
            }
            @Override
            public byte[] getPSK(byte[] identity) {
                return sharedSecretHolder.getServerApplicationSecret();
            }
        });
        this.sharedSecretHolder = sharedSecretHolder;
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions() {
        return new ProtocolVersion[]{ProtocolVersion.TLSv12};
    }

    @Override
    protected int[] getSupportedCipherSuites() {
        if(sharedSecretHolder.getSymmetricalAlgName().toLowerCase().equals("aes")){
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
