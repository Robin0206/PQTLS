package client;

import crypto.SharedSecretHolder;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class ClientPSKConnection extends PSKTlsClient {
    private final SharedSecretHolder sharedSecretHolder;
    private final byte[] identity;
    private final byte[] key;

    public ClientPSKConnection(SharedSecretHolder sharedSecretHolder) {
        super(new BcTlsCrypto(), "identity".getBytes(), sharedSecretHolder.getServerApplicationSecret());
        identity = "identity".getBytes();
        this.sharedSecretHolder = sharedSecretHolder;
        this.key = sharedSecretHolder.getServerApplicationSecret();
    }

    @Override
    public TlsPSKIdentity getPSKIdentity() {
        //Since the client and the server use the key from the key schedule they always use the same key
        //Therefore they don't need to use any identifiers, the identifier is always fixed to "identity".getBytes()
        return new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {

            }

            @Override
            public void notifyIdentityHint(byte[] bytes) {

            }

            @Override
            public byte[] getPSKIdentity() {
                return identity;
            }

            @Override
            public byte[] getPSK() {
                return key;
            }
        };
    }

    @Override
    public TlsSession getSessionToResume() {
        return null;
    }

    @Override
    public TlsAuthentication getAuthentication(){
        //Authentication is not needed because the server is already authenticated
        return new TlsAuthentication() {
            @Override
            public void notifyServerCertificate(TlsServerCertificate serverCertificate){
            }

            @Override
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest){
                return null;
            }
        };
    }

    //For some reason that's not apparent from any documentation PSK only works with TLS 1.2
    @Override
    protected ProtocolVersion[] getSupportedVersions() {
        return new ProtocolVersion[]{ProtocolVersion.TLSv12};
    }

    //chooses the TLS_PSK cipher suite using the symmetrical cipher and hash function that the chosen PQTLSCipherSuite uses
    @Override
    protected int[] getSupportedCipherSuites() {
        if(sharedSecretHolder.getSymmetricalAlgName().toLowerCase() == "aes"){
            return new int[]{
                    CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384
            };
        }else{
            return new int[]{
                    CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
            };
        }
    }
}
