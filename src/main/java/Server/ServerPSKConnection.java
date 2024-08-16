package Server;


import crypto.SharedSecretHolder;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;

/**
 * @author Robin Kroker
 */
public class ServerPSKConnection extends PSKTlsServer {

    private final SharedSecretHolder sharedSecretHolder;

    /**
     * Constructor that sets the sharedSecretHolder and calls super()
     * @param tlsCrypto
     * @param sharedSecretHolder
     */
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
    /**
     * For some reason, that's not apparent from any documentation, PSK only works with TLS 1.2
     * @return
     */
    @Override
    protected ProtocolVersion[] getSupportedVersions() {
        return new ProtocolVersion[]{ProtocolVersion.TLSv12};
    }
    /**
     * chooses the TLS_PSK cipher suite using the symmetrical cipher and hash function that the chosen PQTLSCipherSuite uses
     * @return
     */
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
    /**
     * Needs to be overwritten.
     * In this use case we don't need the method to return anything
     * @return
     */
    @Override
    public TlsSession getSessionToResume(byte[] sessionID) {
        return null;
    }
}
