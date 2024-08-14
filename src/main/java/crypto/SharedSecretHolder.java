package crypto;

import crypto.enums.PQTLSCipherSuite;
import misc.ByteUtils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Objects;


// Main source is https://www.rfc-editor.org/rfc/rfc8446
// The constructor and the method deriveSecretsAfterFinish together exactly follow the figure on page 93
public class SharedSecretHolder {
    PQTLSCipherSuite cipherSuite;
    String
            hashName,
            hMacName;
    byte[]
            zeroes,
            sharedSecret,
            concatenatedHelloMessages,
            clientHelloMessage,
            PSK,
            concatenatedMessagesHelloToFinish;
    byte[]
            earlySecret,
            binderKey,
            clientEarlyTrafficSecret,
            earlyExporterMasterSecret,
            derivedSecret0,
            handShakeSecret,
            clientHandshakeTrafficSecret,
            serverHandshakeTrafficSecret,
            derivedSecret1,
            masterSecret,
            clientApplicationTrafficSecret0,
            serverApplicationTrafficSecret0,
            exporterMasterSecret,
            resumptionMasterSecret,
            clientWriteIV,
            serverWriteIV;
    private String symmetricAlgName;
    int nonceIVSize;



    public SharedSecretHolder(byte[] sharedSecret, byte[] concatenatedHelloMessages, byte[] clientHelloMessage, PQTLSCipherSuite cipherSuite) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        this.sharedSecret = sharedSecret;
        this.concatenatedHelloMessages = concatenatedHelloMessages;
        this.clientHelloMessage = clientHelloMessage;
        this.hashName = deriveHashNameFromCipherSuite(cipherSuite);
        this.hMacName = "hmac" + this.hashName;
        this.zeroes = new byte[MessageDigest.getInstance(this.hashName, "BC").getDigestLength()];
        this.PSK = zeroes;//https://www.rfc-editor.org/rfc/rfc8446 p. 94 z. 9-10
        this.cipherSuite = cipherSuite;
        this.setCipherSuiteAndSymmetricalAlgorithm(cipherSuite);
        this.nonceIVSize = this.symmetricAlgName.toLowerCase() == "aes" ? 32 : 12;

        deriveServerAndClientIV();// https://www.rfc-editor.org/rfc/rfc8446 p. 95, z. 8
        deriveEarlySecret();

        deriveBinderKey();
        deriveClientEarlyTrafficSecret();
        deriveEarlyExporterMasterSecret();
        deriveDerivedSecret0();

        deriveHandShakeSecret();

        deriveClientHandshakeTrafficSecret();
        deriveServerHandshakeTrafficSecret();
        deriveDerivedSecret1();

        deriveMasterSecret();
    }

    private String deriveHashNameFromCipherSuite(PQTLSCipherSuite cipherSuite) {
        String[] cipherSuiteSplit = cipherSuite.toString().split("_");
        return cipherSuiteSplit[cipherSuiteSplit.length-1].toLowerCase();
    }

    private void setCipherSuiteAndSymmetricalAlgorithm(PQTLSCipherSuite cipherSuite) {
        this.cipherSuite = cipherSuite;
        String[] cipherSuiteSplit = cipherSuite.name().split("_");
        for (int i = 0; i < cipherSuiteSplit.length; i++) {
            if (Objects.equals(cipherSuiteSplit[i], "WITH")) {
                this.symmetricAlgName = cipherSuiteSplit[i + 1];
                break;
            }
        }
    }


    public void deriveSecretsAfterFinish(byte[] concatenatedMessagesHelloToFinish) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        this.concatenatedMessagesHelloToFinish = concatenatedMessagesHelloToFinish;
        deriveClientApplicationTrafficSecret();
        deriveServerApplicationTrafficSecret();
        deriveExporterMasterSecret();
        deriveResumptionMasterSecret();
    }

    private void deriveResumptionMasterSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        resumptionMasterSecret = CryptographyModule.hashing.deriveSecret(
                exporterMasterSecret,
                "res master".getBytes(),
                concatenatedMessagesHelloToFinish,
                hashName
        );
    }

    private void deriveExporterMasterSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        exporterMasterSecret = CryptographyModule.hashing.deriveSecret(
                serverApplicationTrafficSecret0,
                "exp master".getBytes(),
                concatenatedMessagesHelloToFinish,
                hashName
        );
    }

    private void deriveServerApplicationTrafficSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        serverApplicationTrafficSecret0 = CryptographyModule.hashing.deriveSecret(
                clientApplicationTrafficSecret0,
                "s ap traffic".getBytes(),
                concatenatedMessagesHelloToFinish,
                hashName,
                32
        );
    }

    private void deriveClientApplicationTrafficSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        clientApplicationTrafficSecret0 = CryptographyModule.hashing.deriveSecret(
                masterSecret,
                "c ap traffic".getBytes(),
                concatenatedMessagesHelloToFinish,
                hashName,
                32
        );
    }

    private void deriveMasterSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        masterSecret = CryptographyModule.hashing.hkdfExtract(
                derivedSecret1,
                zeroes,
                hMacName
        );
    }

    private void deriveDerivedSecret1() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        derivedSecret1 = CryptographyModule.hashing.deriveSecret(
                serverHandshakeTrafficSecret,
                "derived".getBytes(),
                new byte[]{},
                hashName
        );
    }

    private void deriveServerHandshakeTrafficSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        serverHandshakeTrafficSecret = CryptographyModule.hashing.deriveSecret(
                clientHandshakeTrafficSecret,
                "s hs traffic".getBytes(),
                concatenatedHelloMessages,
                hashName,
                32
        );
    }

    private void deriveClientHandshakeTrafficSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        clientHandshakeTrafficSecret = CryptographyModule.hashing.deriveSecret(
                handShakeSecret,
                "c hs traffic".getBytes(),
                concatenatedHelloMessages,
                hashName,
                32
        );
    }

    private void deriveHandShakeSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        handShakeSecret = CryptographyModule.hashing.hkdfExtract(
                derivedSecret0,
                sharedSecret,
                hMacName
        );
    }

    private void deriveDerivedSecret0() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        derivedSecret0 = CryptographyModule.hashing.deriveSecret(
                earlyExporterMasterSecret,
                "derived".getBytes(),
                clientHelloMessage,
                hashName
        );
    }

    private void deriveEarlyExporterMasterSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        earlyExporterMasterSecret = CryptographyModule.hashing.deriveSecret(
                clientEarlyTrafficSecret,
                "e exp master".getBytes(),
                clientHelloMessage,
                hashName
        );
    }

    private void deriveClientEarlyTrafficSecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        clientEarlyTrafficSecret = CryptographyModule.hashing.deriveSecret(
                binderKey,
                "c e traffic".getBytes(),
                clientHelloMessage,
                hashName
        );
    }

    private void deriveBinderKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        binderKey = CryptographyModule.hashing.deriveSecret(
                earlySecret,
                "ext binderresbinder".getBytes(),
                new byte[]{},
                hashName
        );
    }

    private void deriveEarlySecret() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        earlySecret = CryptographyModule.hashing.hkdfExtract(
                zeroes,
                sharedSecret,
                hMacName
        );
    }

    // https://www.rfc-editor.org/rfc/rfc8446 p. 95, z. 8
    private void deriveServerAndClientIV() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] iv = CryptographyModule.hashing.hkdfExpandLabel(
                sharedSecret,
                hMacName,
                "iv".getBytes(),
                "".getBytes(),
                this.nonceIVSize
        );
        serverWriteIV = iv;
        clientWriteIV = iv;
    }

    public boolean equals(SharedSecretHolder sharedSecretHolder) {
        return
                Arrays.equals(earlySecret, sharedSecretHolder.earlySecret) &&
                Arrays.equals(binderKey, sharedSecretHolder.binderKey) &&
                Arrays.equals(clientEarlyTrafficSecret, sharedSecretHolder.clientEarlyTrafficSecret) &&
                Arrays.equals(earlyExporterMasterSecret, sharedSecretHolder.earlyExporterMasterSecret) &&
                Arrays.equals(derivedSecret0, sharedSecretHolder.derivedSecret0) &&
                Arrays.equals(handShakeSecret, sharedSecretHolder.handShakeSecret) &&
                Arrays.equals(clientHandshakeTrafficSecret, sharedSecretHolder.clientHandshakeTrafficSecret) &&
                Arrays.equals(serverHandshakeTrafficSecret, sharedSecretHolder.serverHandshakeTrafficSecret) &&
                Arrays.equals(derivedSecret1, sharedSecretHolder.derivedSecret1) &&
                Arrays.equals(masterSecret, sharedSecretHolder.masterSecret) &&
                Arrays.equals(clientApplicationTrafficSecret0, sharedSecretHolder.clientApplicationTrafficSecret0) &&
                Arrays.equals(serverApplicationTrafficSecret0, sharedSecretHolder.serverApplicationTrafficSecret0) &&
                Arrays.equals(exporterMasterSecret, sharedSecretHolder.exporterMasterSecret) &&
                Arrays.equals(resumptionMasterSecret, sharedSecretHolder.resumptionMasterSecret) &&
                Arrays.equals(clientWriteIV, sharedSecretHolder.clientWriteIV) &&
                Arrays.equals(serverWriteIV, sharedSecretHolder.serverWriteIV);
    }

    public byte[] getServerHandShakeIVAndIncrement() {
        byte[] result = serverWriteIV.clone();
        ByteUtils.increment(serverWriteIV);
        return result;
    }

    public byte[] getClientHandShakeIVAndIncrement() {
        byte[] result = clientWriteIV.clone();
        ByteUtils.increment(clientWriteIV);
        return result;
    }

    public byte[] getServerHandShakeSecret() {
        return serverHandshakeTrafficSecret;
    }

    public byte[] getClientHandShakeSecret() {
        return clientHandshakeTrafficSecret;
    }

    public String getHashName() {
        return hashName;
    }

    public void setSymmetricAlgName(String symmetricAlgName) {
        this.symmetricAlgName = symmetricAlgName;
    }

    public String getSymmetricalAlgName() {
        return symmetricAlgName;
    }

    public PQTLSCipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public void printApplicationTrafficSecrets(){
        System.out.println("Client: " + Arrays.toString(clientApplicationTrafficSecret0));
        System.out.println("Server: " + Arrays.toString(serverApplicationTrafficSecret0));
    }
}
