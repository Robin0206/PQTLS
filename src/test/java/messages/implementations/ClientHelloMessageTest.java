package messages.implementations;

import crypto.CipherSuite;
import messages.extensions.PQTLSExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ClientHelloMessageTest {
    static ClientHelloMessage message1;
    static ClientHelloMessage message2;
    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        message1 = new ClientHelloMessage.ClientHelloBuilder()
                .extensions(new PQTLSExtension[]{})
                .cipherSuites(new CipherSuite[]{
                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_FRODOKEM_FALCON_WITH_CHACHA20_256_POLY1305_SHA384
                })
                .protocolVersion((short)0x0301)
                .sessionID(new byte[32])
                .build();
    }

    @Test
    void testBuildFromBytes(){
        message2 = new ClientHelloMessage.ClientHelloBuilder().fromBytes(message1.getBytes()).build();
        assertTrue(message1.equals(message2));
    }
    @Test
    void testClientRandomIsNotNull(){
        message2 = new ClientHelloMessage.ClientHelloBuilder().fromBytes(message1.getBytes()).build();

        assertAll(()->{
            assertNotNull(message1.getClientRandom());
            assertNotNull(message2.getClientRandom());
        });
    }
    @Test
    void testCallingBuildThrowsExceptionIfSomethingIsNotSet(){
        assertAll(()->{
            assertThrows(Exception.class,
                    ()->{
                        message2 = new ClientHelloMessage.ClientHelloBuilder()
                                .extensions(new PQTLSExtension[]{})
                                .protocolVersion((short)0x0301)
                                .sessionID(new byte[32])
                                .build();
                    }
            );
            assertThrows(Exception.class,
                    ()->{
                        message2 = new ClientHelloMessage.ClientHelloBuilder()
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
                        message2 = new ClientHelloMessage.ClientHelloBuilder()
                                .cipherSuites(new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                                })
                                .extensions(new PQTLSExtension[]{})
                                .protocolVersion((short)0x0301)
                                .build();
                    }
            );
            assertThrows(Exception.class,
                    ()->{
                        message2 = new ClientHelloMessage.ClientHelloBuilder()
                                .cipherSuites(new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                                })
                                .protocolVersion((short)0x0301)
                                .sessionID(new byte[32])
                                .build();
                    }
            );
        });
    }
    @Test
    void testCallingOtherBuilderMethodsWithFromBytesLeadsToBuildThrowingException(){

        assertThrows(Exception.class, ()->{
            message2 = new ClientHelloMessage.ClientHelloBuilder()
                    .cipherSuites(new CipherSuite[]{
                            CipherSuite.TLS_ECDHE_FRODOKEM_DILITHIUM_WITH_AES_256_GCM_SHA384,
                            CipherSuite.TLS_ECDHE_FRODOKEM_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384
                    })
                    .fromBytes(message1.getBytes())
                    .build();
        });
    }
}