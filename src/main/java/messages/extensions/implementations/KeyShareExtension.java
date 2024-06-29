package messages.extensions.implementations;

import messages.extensions.PQTLSExtension;

import java.util.ArrayList;
import java.util.Arrays;

import static misc.Constants.*;

//Key Share extension
//Byte structure modified to allow for multiple keys
//{0x00, 0x33}=Identifier||..numOfFollowingBytes..||..EC parameter..||..number of keys..||..up to three keyLength Fields..||..Keys..||
//-------2 bytes---------||-------2 bytes---------||----2 bytes-----||-------1 byte-----||-------2 bytes per field--------||
public class KeyShareExtension implements PQTLSExtension {

    byte[][] keys;
    byte[][] keyLengths;
    byte[] byteRepresentation;
    byte[] ecParameter;
    public KeyShareExtension(byte[][] keys, byte[] ecParameter){
        throwExceptionIfNecessary(keys, ecParameter);
        this.keys = keys;
        this.ecParameter = ecParameter;
        fillKeyLengths();
        fillBytes();
    }

    private void fillBytes() {
        ArrayList<Byte> buffer = fillByteBuffer();
        // convert to normal array
        int byteRepresentationLength = buffer.size();
        byteRepresentation = new byte[byteRepresentationLength];
        for (int i = 0; i < buffer.size(); i++) {
            byteRepresentation[i] = buffer.get(i);
        }
        //calculate the num of following bytes
        int numOfFollowingBytes = byteRepresentationLength - 4;
        byteRepresentation[2] = (byte) (numOfFollowingBytes /128);
        byteRepresentation[3] = (byte) (numOfFollowingBytes%128);
    }

    private ArrayList<Byte> fillByteBuffer() {
        ArrayList<Byte> buffer = new ArrayList<>();
        //add identifier
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x33);
        //add numOfFollowingBytes as {0x0, 0x0}
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x00);
        //add ec parameter
        buffer.add(ecParameter[0]);
        buffer.add(ecParameter[1]);
        //add number of keys
        buffer.add((byte)keys.length);
        //add keyLength fields
        for(byte[] keyLength : keyLengths){
            for(byte b : keyLength){
                buffer.add(b);
            }
        }
        //add keys
        for(byte[] key : keys){
            for(byte b : key){
                buffer.add(b);
            }
        }
        return buffer;
    }

    private static void throwExceptionIfNecessary(byte[][] keys, byte[] ecParameter) {
        if(ecParameter.length != EC_PARAMETER_LENGTH){
            throw new IllegalArgumentException("EC parameters length is always 2 bytes");
        }else if(keys.length == 0 || keys.length > EXTENSION_KEY_SHARE_MAX_KEY_ARR_LENGTH){
            throw new IllegalArgumentException("Invalid number of keys");
        }
    }

    private void fillKeyLengths() {

        keyLengths = new byte[keys.length][EXTENSION_KEY_SHARE_KEY_LENGTH_FIELD_LENGTH];
        for (int i = 0; i < keys.length; i++) {
            if(keys[i].length != 1088 && keys[i].length != 168 && keys[i].length != 93){
                throw new IllegalArgumentException(String.valueOf(keys[i].length));
            }
            this.keyLengths[i][0] = (byte)(keys[i].length/128);
            this.keyLengths[i][1] = (byte)(keys[i].length%128);
        }
    }

    @Override
    public byte[] getByteRepresentation() {
        return byteRepresentation;
    }


    @Override
    public void printVerbose() {
        System.out.println("=====Extension: Key Share");
        System.out.println("Keys:");
        for (int i = 0; i < keys.length; i++) {
            System.out.println("\tKey " + i + ": " + Arrays.toString(keys[i]));
            System.out.println("\tKeyLength: " + Arrays.toString(keyLengths[i]) + " = " + keys[i].length);
        }
        System.out.println("Bytes: " + byteRepresentation.length);
        System.out.println(Arrays.toString(byteRepresentation));
    }

    @Override
    public byte getIdentifier() {
        return EXTENSION_IDENTIFIER_KEY_SHARE;
    }
    public static KeyShareExtension fromBytes(byte[] input) {
        if(input[EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET-1] == 2){
            return buildKeyShareExtensionWithTwoKeys(input);
        }else{
            return buildKeyShareExtensionWithThreeKeys(input);
        }
    }
    private static KeyShareExtension buildKeyShareExtensionWithTwoKeys(byte[] input) {

        //calculate indices
        int curveParameterStartIndex = EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET - 3;

        int firstKeyLengthFieldStartIndex = EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET;

        int secondKeyLengthFieldStartIndex =
                EXTENSION_KEY_SHARE_KEY_LENGTH_FIELD_LENGTH +
                        EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET;

        int firstKeyStartIndex = secondKeyLengthFieldStartIndex + 2;

        int firstKeyLength =
                (input[firstKeyLengthFieldStartIndex] * 128 )+
                        input[firstKeyLengthFieldStartIndex + 1];

        int secondKeyLength =
                input.length -
                        firstKeyStartIndex -
                        firstKeyLength;

        int secondKeyStartIndex =
                firstKeyStartIndex +
                        firstKeyLength;

        //extract the values
        byte[] curveParameter = new byte[]{
                input[curveParameterStartIndex],
                input[curveParameterStartIndex + 1]
        };

        byte[] firstKey = new byte[firstKeyLength];
        System.arraycopy(input, firstKeyStartIndex, firstKey, 0, firstKeyLength);

        byte[] secondKey = new byte[secondKeyLength];
        System.arraycopy(input, secondKeyStartIndex, secondKey, 0, secondKeyLength);
        return new KeyShareExtension(
                new byte[][]{firstKey, secondKey},
                curveParameter
        );

    }

    private static KeyShareExtension buildKeyShareExtensionWithThreeKeys(byte[] input) {

        //calculate indices
        int curveParameterStartIndex = EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET - 3;

        int firstKeyLengthFieldStartIndex = EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET;

        int secondKeyLengthFieldStartIndex =
                EXTENSION_KEY_SHARE_KEY_LENGTH_FIELD_LENGTH +
                        EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET;

        int thirdKeyLengthFieldStartIndex =
                2 * EXTENSION_KEY_SHARE_KEY_LENGTH_FIELD_LENGTH +
                        EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET;

        int firstKeyStartIndex = secondKeyLengthFieldStartIndex + 2;

        int firstKeyLength =
                input[firstKeyLengthFieldStartIndex] * 128 +
                        input[firstKeyLengthFieldStartIndex + 1];

        int secondKeyStartIndex =
                firstKeyStartIndex +
                        firstKeyLength;

        int secondKeyLength =
                input[secondKeyLengthFieldStartIndex] * 128 +
                        input[secondKeyLengthFieldStartIndex + 1];

        int thirdKeyStartIndex =
                secondKeyStartIndex +
                        secondKeyLength;
        int thirdKeyLength=
                input[thirdKeyLengthFieldStartIndex] * 128 +
                        input[thirdKeyLengthFieldStartIndex + 1];

        //extract the values
        byte[] curveParameter = new byte[]{
                input[curveParameterStartIndex],
                input[curveParameterStartIndex + 1]
        };

        byte[] firstKey = new byte[firstKeyLength];
        System.arraycopy(input, firstKeyStartIndex, firstKey, 0, firstKeyLength);

        byte[] secondKey = new byte[secondKeyLength];
        System.arraycopy(input, secondKeyStartIndex, secondKey, 0, secondKeyLength);

        byte[] thirdKey = new byte[thirdKeyLength];
        System.arraycopy(input, thirdKeyStartIndex, thirdKey, 0, thirdKeyLength);
        return new KeyShareExtension(
                new byte[][]{firstKey, secondKey, thirdKey},
                curveParameter
        );

    }
    public boolean equals(KeyShareExtension keyShareExtension){
        return
                java.util.Arrays.deepEquals(this.keys, keyShareExtension.keys) &&
                java.util.Arrays.deepEquals(this.keyLengths, keyShareExtension.keyLengths) &&
                java.util.Arrays.equals(this.ecParameter, keyShareExtension.ecParameter) &&
                java.util.Arrays.equals(this.byteRepresentation, keyShareExtension.byteRepresentation);

    }
}
