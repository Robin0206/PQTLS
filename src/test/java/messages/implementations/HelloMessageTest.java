package messages.implementations;

import crypto.CipherSuite;
import messages.extensions.PQTLSExtension;
import misc.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

class HelloMessageTest {
    static HelloMessage message1;
    static HelloMessage message2;
    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        Security.addProvider(new BouncyCastleProvider());
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        message1 = new HelloMessage.HelloBuilder()
                .extensions(new PQTLSExtension[]{})
                .cipherSuites(new CipherSuite[]{
                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_FRODOKEM_FALCON_WITH_CHACHA20_256_POLY1305_SHA384
                })
                .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_CLIENT_HELLO)
                .random(random)
                .LegacyVersion(new byte []{0x03, 0x03})
                .sessionID(new byte[32])
                .build();
    }

    @Test
    void testBuildFromBytes(){
        message2 = new HelloMessage.HelloBuilder().fromBytes(message1.getBytes()).build();
        assertTrue(message1.equals(message2));
    }
    @Test
    void testClientRandomIsNotNull(){
        message2 = new HelloMessage.HelloBuilder().fromBytes(message1.getBytes()).build();

        assertAll(()->{
            assertNotNull(message1.getRandom());
            assertNotNull(message2.getRandom());
        });
    }
    @Test
    void testCallingBuildThrowsExceptionIfSomethingIsNotSet(){
        assertAll(()->{
            assertThrows(Exception.class,
                    ()->{
                        message2 = new HelloMessage.HelloBuilder()
                                .extensions(new PQTLSExtension[]{})
                                .LegacyVersion(new byte[]{0x03, 0x03})
                                .sessionID(new byte[32])
                                .build();
                    }
            );
            assertThrows(Exception.class,
                    ()->{
                        message2 = new HelloMessage.HelloBuilder()
                                .cipherSuites(new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                                })
                                .extensions(new PQTLSExtension[]{})
                                .sessionID(new byte[32])
                                .build();
                    }
            );
            assertThrows(Exception.class,
                    ()->{
                        message2 = new HelloMessage.HelloBuilder()
                                .cipherSuites(new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                                })
                                .extensions(new PQTLSExtension[]{})
                                .LegacyVersion(new byte[]{0x03, 0x03})
                                .build();
                    }
            );
            assertThrows(Exception.class,
                    ()->{
                        message2 = new HelloMessage.HelloBuilder()
                                .cipherSuites(new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                                })
                                .LegacyVersion(new byte[]{0x03, 0x03})
                                .sessionID(new byte[32])
                                .build();
                    }
            );
        });
    }
    @Test
    void testCallingOtherBuilderMethodsWithFromBytesLeadsToBuildThrowingException(){

        assertThrows(Exception.class, ()->{
            message2 = new HelloMessage.HelloBuilder()
                    .cipherSuites(new CipherSuite[]{
                            CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                            CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                    })
                    .fromBytes(message1.getBytes())
                    .build();
        });
    }

    @Test
    void testInvalidCipherSuiteShouldThrowException(){
        assertAll(()->{
            assertThrows(Exception.class, ()->{
                message2 = new HelloMessage.HelloBuilder()
                        .cipherSuites(
                                new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                                }
                        )
                        .random(new byte[32])
                        .LegacyVersion(new byte[]{0x03, 0x03})
                        .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO)
                        .extensions(new PQTLSExtension[0])
                        .sessionID(new byte[32])
                        .build();
            });
            assertThrows(Exception.class, ()->{
                message2 = new HelloMessage.HelloBuilder()
                        .random(new byte[32])
                        .LegacyVersion(new byte[]{0x03, 0x03})
                        .handShakeType(Constants.HELLO_MESSAGE_HANDSHAKE_TYPE_SERVER_HELLO)
                        .cipherSuites(
                                new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                                }
                        )
                        .extensions(new PQTLSExtension[0])
                        .sessionID(new byte[32])
                        .build();
            });
        });

    }
}