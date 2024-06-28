package messages.extensions;

import java.util.Arrays;

import static misc.Constants.*;
//Signature Algorithms extension
//Byte structure modified since there are now only 2 signature algorithms to choose from
//||....{0x00, 0x0d}=identifier....||....numOfFollowingBytes....||....SignatureAlgIdentifierBytes....||
//||----------2 bytes--------------||---------1 byte--------||
//Signature Algorithm Byte values:
// 0x00 = supports Sphincs
// 0x01 = supports Dilithium
// 0x02 = supports Falcon
public class SignatureAlgorithmsExtension implements PQTLSExtension{
    byte[] supportedSignatureAlgorithms;
    byte[] byteRepresentation;
    public SignatureAlgorithmsExtension(byte[] supportedSignatureAlgorithms){
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
        fillByteRepresentation();
    }

    private void fillByteRepresentation() {
        byteRepresentation = new byte[EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET + supportedSignatureAlgorithms.length];
        byteRepresentation[0] = 0x00;
        byteRepresentation[1] = 0x0d;
        byteRepresentation[3] = (byte)supportedSignatureAlgorithms.length;
        System.arraycopy(
                supportedSignatureAlgorithms,
                0,
                byteRepresentation,
                EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET,
                byteRepresentation.length - EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTED_ALGORITHMS_OFFSET
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
                case EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_FALCON:
                    System.out.println("\t supports falcon");
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
}
