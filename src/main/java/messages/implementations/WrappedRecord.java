package messages.implementations;

import crypto.CryptographyModule;
import crypto.enums.CipherSuite;
import messages.PQTLSMessage;
import misc.ByteUtils;
import org.bouncycastle.util.Strings;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

public class WrappedRecord implements PQTLSMessage {
    PQTLSMessage messageToWrap;
    byte actualRecordType;
    byte[] encryptedMessage;
    Key key;
    byte[] messageBytes;
    byte[] decryptedMessageToWrapBytes;

    //Constructor that takes the message as an PQTLSMessage Object and also encrypts the message
    public WrappedRecord(
            PQTLSMessage messageToWrap,
            byte actualRecordType,
            Key key,
            byte[] iv_nonce,
            CipherSuite cipherSuite
    ) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        this.messageToWrap = messageToWrap;
        this.decryptedMessageToWrapBytes = messageToWrap.getBytes();
        this.actualRecordType = actualRecordType;
        this.key = key;
        if (Objects.equals(getSymmetricCipherNameFromCipherSuite(cipherSuite), "AES")) {
            encryptedMessage = CryptographyModule.symmetric.encryptAES(messageToWrap.getBytes(), iv_nonce, key);
        } else {
            encryptedMessage = CryptographyModule.symmetric.encryptChaCha(messageToWrap.getBytes(), iv_nonce, key);
        }
        fillMessageBytes();
    }

    //Constructor that takes the message as an PQTLSMessage Object and also decrypts the message
    public WrappedRecord(
            byte[] messageBytes,
            Key key,
            byte[] iv_nonce,
            CipherSuite cipherSuite
    ) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        this.messageBytes = messageBytes;
        actualRecordType = messageBytes[messageBytes.length - 1];
        this.key = key;
        setEncryptedMessage();
        setDecryptedMessage(cipherSuite, iv_nonce);
    }

    private void setDecryptedMessage(CipherSuite cipherSuite, byte[] iv_nonce) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        byte[] decryptedMessageBytes;
        if (Objects.equals(getSymmetricCipherNameFromCipherSuite(cipherSuite), "AES")) {
            decryptedMessageBytes = CryptographyModule.symmetric.decryptAES(encryptedMessage, iv_nonce, key);
        } else {
            decryptedMessageBytes = CryptographyModule.symmetric.decryptChaCha(encryptedMessage, iv_nonce, key);
        }
        messageToWrap = bytesToPQTLSExtension(decryptedMessageBytes);
        decryptedMessageToWrapBytes = decryptedMessageBytes;
    }

    private void setEncryptedMessage() {
        encryptedMessage = new byte[messageBytes.length - 6];
        System.arraycopy(
                messageBytes,
                5,
                encryptedMessage,
                0,
                encryptedMessage.length
        );
    }

    private void fillMessageBytes() {
        ArrayList<Byte> buffer = new ArrayList<>();
        //add type
        buffer.add((byte) 0x17);
        //add legacy version
        buffer.add((byte) 0x03);
        buffer.add((byte) 0x03);
        //add 2 zero bytes for num of following bytes
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x00);
        //add encrypted content
        for (byte b : encryptedMessage) {
            buffer.add(b);
        }
        //add actual record type
        buffer.add(actualRecordType);
        messageBytes = new byte[buffer.size()];
        for (int i = 0; i < buffer.size(); i++) {
            messageBytes[i] = buffer.get(i);
        }
        byte[] numOfFollowingBytes = ByteUtils.shortToByteArr((short) (buffer.size() - 5));
        messageBytes[3] = numOfFollowingBytes[0];
        messageBytes[4] = numOfFollowingBytes[1];
    }


    private String getSymmetricCipherNameFromCipherSuite(CipherSuite cipherSuite) {
        String[] cipherSuiteContentSplit = Strings.split(cipherSuite.name(), '_');
        for (int i = 0; i < cipherSuiteContentSplit.length; i++) {
            if (Objects.equals(cipherSuiteContentSplit[i], "WITH")) {
                return cipherSuiteContentSplit[i + 1];
            }
        }
        return null;
    }

    public PQTLSMessage bytesToPQTLSExtension(byte[] decryptedMessageBytes) throws IOException {
        return switch (decryptedMessageBytes[0]) {
            case 0x08 -> new EncryptedExtensions(decryptedMessageBytes);
            case 0x0b -> new CertificateMessage(decryptedMessageBytes);
            case 0x0f -> new CertificateVerifyMessage(decryptedMessageBytes);
            case 0x14 -> new FinishedMessage(decryptedMessageBytes);
            case (byte) 0xff -> new NullMessage();
            default -> throw new IllegalArgumentException("Invalid Identifier in Handshake header!");
        };
    }

    @Override
    public byte[] getBytes() {
        return messageBytes;
    }

    @Override
    public void printVerbose() {
        System.out.println("===================================Wrapped Record===================================");
        System.out.println("RecordType:      " + 0x17);
        System.out.println("LegacyVersion: " + java.util.Arrays.toString(new byte[]{0x03, 0x03}));
        System.out.println("LengthAfterRecordHeader: " + Arrays.toString(ByteUtils.shortToByteArr((short) (messageBytes.length - 5))));
        System.out.println("Application Data " + Arrays.toString(encryptedMessage));
        System.out.println("Actual RecordType: " + actualRecordType);
    }

    public PQTLSMessage getWrappedMessage() {
        return messageToWrap;
    }

    public boolean equals(PQTLSMessage wrappedRecord) {
        WrappedRecord castMessage = (WrappedRecord) wrappedRecord;
        return this.actualRecordType == castMessage.actualRecordType &&
                Arrays.equals(this.encryptedMessage, castMessage.encryptedMessage) &&
                Arrays.equals(this.key.getEncoded(), castMessage.key.getEncoded()) &&
                Arrays.equals(this.messageBytes, castMessage.messageBytes) &&
                Arrays.equals(this.decryptedMessageToWrapBytes, castMessage.decryptedMessageToWrapBytes);
    }
}
