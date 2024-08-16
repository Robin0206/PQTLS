package messages.extensions.implementations;

import messages.extensions.PQTLSExtension;

import java.util.Arrays;

import static misc.Constants.*;
/**
 * @author Robin Kroker
 * Signature Algorithms extension
 * Byte structure simplified since there are only 2 signature algorithms to choose from
 * inspired by https://www.rfc-editor.org/rfc/rfc8446 section 4.2.3
 * ||....{0x00, 0x0d}=identifier....||....numOfFollowingBytes....||....SignatureAlgIdentifierBytes....||
 * ||----------2 bytes--------------||---------2 bytes-----------||
 * Signature Algorithm Byte values:
 * 0x00 = supports Sphincs
 * 0x01 = supports Dilithium
 */
public class SignatureAlgorithmsExtension implements PQTLSExtension {
    final byte[] supportedSignatureAlgorithms;
    byte[] byteRepresentation;
    public SignatureAlgorithmsExtension(byte[] supportedSignatureAlgorithms){
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
        fillByteRepresentation();
    }

    private void fillByteRepresentation() {
        byteRepresentation = new byte[EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET + supportedSignatureAlgorithms.length];
        byteRepresentation[0] = 0x00;
        byteRepresentation[1] = 0x0d;
        byteRepresentation[2] = 0;
        byteRepresentation[3] = (byte)supportedSignatureAlgorithms.length;
        System.arraycopy(
                supportedSignatureAlgorithms,
                0,
                byteRepresentation,
                EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET,
                supportedSignatureAlgorithms.length
        );
    }

    public static PQTLSExtension fromBytes(byte[] input) {
        byte[] supportedAlgorithms = new byte[input.length - EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET];
        System.arraycopy(
                input,
                EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET,
                supportedAlgorithms,
                0,
                supportedAlgorithms.length
        );
        return new SignatureAlgorithmsExtension(supportedAlgorithms);
    }

    @Override
    public byte[] getByteRepresentation() {
        return byteRepresentation;
    }

    @Override
    public void printVerbose() {
        System.out.println("=====Extension: Signature Algorithms");
        for(byte b : supportedSignatureAlgorithms){
            switch(b){
                case EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_SPHINCS:
                    System.out.println("\t supports sphincs");
                    break;
                case EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM:
                    System.out.println("\t supports dilithium");
                    break;
            }
        }
    }

    @Override
    public byte getIdentifier() {
        return EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS;
    }

    public boolean equals(SignatureAlgorithmsExtension signatureAlgorithmsExtension){
        return Arrays.equals(this.byteRepresentation, signatureAlgorithmsExtension.byteRepresentation);
    }

    public byte[] getSupportedSignatureAlgorithms() {
        return supportedSignatureAlgorithms;
    }
}
