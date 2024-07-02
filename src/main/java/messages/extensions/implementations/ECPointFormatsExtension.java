package messages.extensions.implementations;

import crypto.enums.ECPointFormat;
import messages.extensions.PQTLSExtension;
import misc.ByteUtils;
import misc.Constants;

import java.util.ArrayList;

/*
||...identifier...||...numOfFollowingBytes...||...values...||
||-----2 bytes----||--------2 bytes..........||
 */
public class ECPointFormatsExtension implements PQTLSExtension {

    private final ECPointFormat[] ecPointFormats;
    private byte[] byteRepresentation;

    public ECPointFormatsExtension(ECPointFormat[] ecPointFormats){
        this.ecPointFormats = ecPointFormats;
        fillByteRepresentation();
    }

    private void fillByteRepresentation() {
        byteRepresentation = new byte[ecPointFormats.length + 4];
        byteRepresentation[0] = 0x00;
        byteRepresentation[1] = Constants.EXTENSION_IDENTIFIER_EC_POINT_FORMATS;
        byte[] numOfFollowingBytes = ByteUtils.shortToByteArr((short)ecPointFormats.length);
        byteRepresentation[2] = numOfFollowingBytes[0];
        byteRepresentation[3] = numOfFollowingBytes[1];
        for(int i = 0; i < ecPointFormats.length; i++){
            byteRepresentation[i + 4] = (byte)(ecPointFormats[i].ordinal());
        }
    }

    @Override
    public byte[] getByteRepresentation() {
        return byteRepresentation;
    }

    @Override
    public void printVerbose() {
        System.out.println("=====Extension: EC Point Formats");
        for (ECPointFormat ecPointFormat : ecPointFormats) {
            System.out.println("\t" + ecPointFormat.toString());
        }
    }

    @Override
    public byte getIdentifier() {
        return Constants.EXTENSION_IDENTIFIER_EC_POINT_FORMATS;
    }

    public static PQTLSExtension fromBytes(byte[] input){
        ECPointFormat[] formats = new ECPointFormat[input.length-4];
        for(int i = 4; i < input.length; i++){
            formats[i - 4] = ECPointFormat.values()[input[i]];
        }
        return new ECPointFormatsExtension(formats);
    }
}
