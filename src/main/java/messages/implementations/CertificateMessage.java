package messages.implementations;

import messages.PQTLSMessage;
import misc.ByteUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author Robin Kroker
 * Message that the server sends to the client which contains one or more certificate chains from the server
 * The structure is the same as in https://www.rfc-editor.org/rfc/rfc8446 section-4.4.2
 */

public class CertificateMessage implements PQTLSMessage {

    private X509CertificateHolder[] certificates;
    byte[] messageBytes;
    byte[] certificateBytes;
    byte[] requestContext;

    public CertificateMessage(byte[] input) throws IOException {
        messageBytes = input;
        setRequestContextBytes();
        setCertificateBytesFromInputBytes();
        setCertificatesFromCertificateBytes();
    }

    public X509CertificateHolder[] getCertificates() {
        return certificates;
    }

    private void setCertificatesFromCertificateBytes() throws IOException {
        ArrayList<X509CertificateHolder> buffer = new ArrayList<>();
        int index = 0;
        while (index < certificateBytes.length) {
            int currentCertificateLength = ByteUtils.byteArrToInt(new byte[]{
                    certificateBytes[index],
                    certificateBytes[index + 1],
                    certificateBytes[index + 2]
            });
            index += 3;
            ArrayList<Byte> currentCertificateBytes = new ArrayList<>();
            for (int i = 0; i < currentCertificateLength; i++, index++) {
                currentCertificateBytes.add(certificateBytes[index]);
            }
            if(currentCertificateBytes.size() > 3){
                buffer.add(new X509CertificateHolder(ByteUtils.toByteArray(currentCertificateBytes)));
            }

        }
        certificates = new X509CertificateHolder[buffer.size()];
        for (int i = 0; i < buffer.size(); i++) {
            certificates[i] = buffer.get(i);
        }
    }

    private void setCertificateBytesFromInputBytes() {
        int startIndexOfCertificatesLength = getStartIndexOfCertificatesLength();
        certificateBytes = new byte[messageBytes.length - startIndexOfCertificatesLength];
        System.arraycopy(
                messageBytes,
                startIndexOfCertificatesLength + 3,
                certificateBytes,
                0,
                messageBytes.length - (startIndexOfCertificatesLength + 3)
        );
    }

    private int getStartIndexOfCertificatesLength() {
        return messageBytes[4] + 5;
    }

    private void setRequestContextBytes() {
        byte requestContextLength = messageBytes[4];
        requestContext = new byte[requestContextLength];
        System.arraycopy(messageBytes, 5, requestContext, 0, requestContextLength);
    }

    public CertificateMessage(X509CertificateHolder[] input) throws IOException {
        this.certificates = input;
        this.requestContext = new byte[0];
        setCertificateBytes();
        setMessageBytes();
    }

    //also adds the lengths
    private void setCertificateBytes() throws IOException {
        ArrayList<byte[]> buffer = new ArrayList<>();
        for (X509CertificateHolder cert : certificates) {
            byte[] certBytes = cert.getEncoded();
            byte[] certLength = ByteUtils.intToByteArray3(certBytes.length);
            byte[] certWithLength = new byte[certLength.length + certBytes.length];
            System.arraycopy(certLength, 0, certWithLength, 0, certLength.length);
            System.arraycopy(certBytes, 0, certWithLength, certLength.length, certBytes.length);
            buffer.add(certWithLength);
        }
        certificateBytes = ByteUtils.flatten(buffer);
    }

    private void setMessageBytes() {
        ArrayList<Byte> buffer = new ArrayList<>();
        //Add handshake message type
        buffer.add((byte) 0x0b);
        //Add 3 zeroes that will hold the number of following bytes
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x00);
        //Add the length of the requestContext as one byte
        buffer.add((byte) requestContext.length);
        //Add the request Context
        for (byte b : requestContext) {
            buffer.add(b);
        }
        //add the size of the certificates as 3 bytes
        byte[] certificatesLength = ByteUtils.intToByteArray3(certificateBytes.length);
        buffer.add(certificatesLength[0]);
        buffer.add(certificatesLength[1]);
        buffer.add(certificatesLength[2]);
        for (byte b : certificateBytes) {
            buffer.add(b);
        }
        messageBytes = ByteUtils.toByteArray(buffer);
    }

    @Override
    public byte[] getBytes() {
        return messageBytes;
    }

    @Override
    public void printVerbose() throws CertificateException {
        System.out.println("================================Certificate Message=================================");
        for(X509CertificateHolder certificate : certificates){
            System.out.println(new JcaX509CertificateConverter().getCertificate(certificate).toString());
        }
    }

    public boolean equals(PQTLSMessage messageToCast) {
        CertificateMessage message = (CertificateMessage) messageToCast;
        for (int i = 0; i < certificates.length; i++) {
            if (this.certificates[i] != message.certificates[i]) {
                return false;
            }
        }
        return
                Arrays.equals(this.certificateBytes, message.certificateBytes) &&
                Arrays.equals(this.messageBytes, message.messageBytes) &&
                Arrays.equals(this.requestContext, message.requestContext);
    }
}
