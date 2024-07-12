package crypto;

import misc.ByteUtils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;


// Main source is https://www.rfc-editor.org/rfc/rfc8446
// The constructor and the method deriveSecretsAfterFinish together exactly follow the figure on page 93
public class SharedSecret {
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


    public SharedSecret(byte[] sharedSecret, String hashName, byte[] concatenatedHelloMessages, byte[] clientHelloMessage, byte[] PSK) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        this.zeroes = new byte[MessageDigest.getInstance(hashName, "BC").getDigestLength()];
        this.sharedSecret = sharedSecret;
        this.concatenatedHelloMessages = concatenatedHelloMessages;
        this.clientHelloMessage = clientHelloMessage;
        this.PSK = PSK;
        this.hashName = hashName;
        this.hMacName = "hmac" + hashName;

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


    public SharedSecret(byte[] sharedSecret, String hashName, byte[] concatenatedHelloMessages, byte[] clientHelloMessage) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        this.zeroes = new byte[MessageDigest.getInstance(hashName, "BC").getDigestLength()];
        this.sharedSecret = sharedSecret;
        this.concatenatedHelloMessages = concatenatedHelloMessages;
        this.clientHelloMessage = clientHelloMessage;
        this.PSK = zeroes;//https://www.rfc-editor.org/rfc/rfc8446 p. 94 z. 9-10
        this.hashName = hashName;
        this.hMacName = "hmac" + hashName;

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
                32
        );
        serverWriteIV = iv;
        clientWriteIV = iv;
    }

    public boolean equals(SharedSecret sharedSecret) {
        return
                Arrays.equals(earlySecret, sharedSecret.earlySecret) &&
                Arrays.equals(binderKey, sharedSecret.binderKey) &&
                Arrays.equals(clientEarlyTrafficSecret, sharedSecret.clientEarlyTrafficSecret) &&
                Arrays.equals(earlyExporterMasterSecret, sharedSecret.earlyExporterMasterSecret) &&
                Arrays.equals(derivedSecret0, sharedSecret.derivedSecret0) &&
                Arrays.equals(handShakeSecret, sharedSecret.handShakeSecret) &&
                Arrays.equals(clientHandshakeTrafficSecret, sharedSecret.clientHandshakeTrafficSecret) &&
                Arrays.equals(serverHandshakeTrafficSecret, sharedSecret.serverHandshakeTrafficSecret) &&
                Arrays.equals(derivedSecret1, sharedSecret.derivedSecret1) &&
                Arrays.equals(masterSecret, sharedSecret.masterSecret) &&
                Arrays.equals(clientApplicationTrafficSecret0, sharedSecret.clientApplicationTrafficSecret0) &&
                Arrays.equals(serverApplicationTrafficSecret0, sharedSecret.serverApplicationTrafficSecret0) &&
                Arrays.equals(exporterMasterSecret, sharedSecret.exporterMasterSecret) &&
                Arrays.equals(resumptionMasterSecret, sharedSecret.resumptionMasterSecret) &&
                Arrays.equals(clientWriteIV, sharedSecret.clientWriteIV) &&
                Arrays.equals(serverWriteIV, sharedSecret.serverWriteIV);
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
}
