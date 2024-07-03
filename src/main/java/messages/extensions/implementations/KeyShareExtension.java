package messages.extensions.implementations;

import messages.extensions.PQTLSExtension;
import misc.ByteUtils;

import java.util.ArrayList;
import java.util.Arrays;

import static misc.Constants.*;

//Key Share extension
//Byte structure modified to allow for multiple keys
//{0x00, 0x33}=Identifier||..numOfFollowingBytes..||..number of keys..||..keyLength Fields..||..Keys..||
//-------2 bytes---------||-------2 bytes---------||-------1 byte-----||-2 bytes per field--||
//the first keys are ec keys like in the standard case. Depending on the cipher suite, the last keys are the hybrid keys in
//the order there are in the cipher suite
public class KeyShareExtension implements PQTLSExtension {

    byte[][] keys;
    byte[][] keyLengths;
    byte[] byteRepresentation;
    public KeyShareExtension(byte[][] keys){
        throwExceptionIfNecessary(keys);
        this.keys = keys;
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
        byte[] numOfFollowingBytes = ByteUtils.shortToByteArr((short)(byteRepresentationLength - 4));
        byteRepresentation[2] = numOfFollowingBytes[0];
        byteRepresentation[3] = numOfFollowingBytes[1];
    }

    private ArrayList<Byte> fillByteBuffer() {
        ArrayList<Byte> buffer = new ArrayList<>();
        //add identifier
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x33);
        //add numOfFollowingBytes as {0x0, 0x0}
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x00);
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

    private static void throwExceptionIfNecessary(byte[][] keys) {
        if(keys.length < EXTENSION_KEY_SHARE_MIN_KEY_ARR_LENGTH){
            throw new IllegalArgumentException("Invalid number of keys");
        }
    }

    private void fillKeyLengths() {
        keyLengths = new byte[keys.length][EXTENSION_KEY_SHARE_KEY_LENGTH_FIELD_LENGTH];
        for (int i = 0; i < keys.length; i++) {
            this.keyLengths[i] = ByteUtils.shortToByteArr((short)keys[i].length);
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
        return buildKeyShareExtensionWithNKeys(input);
    }

    public static KeyShareExtension buildKeyShareExtensionWithNKeys(byte[] input){

        //extract the keyLengths
        int[] keyLengthIndices = getKeyLengthIndices(input);
        short[] keyLengths = new short[input[EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET-1]];
        int keyLengthIndex = 0;
        for (int i = keyLengthIndices[0]; i < keyLengthIndices[1]; i+=2, keyLengthIndex++) {
            keyLengths[keyLengthIndex] = ByteUtils.byteArrToShort(new byte[]{input[i], input[i+1]});
        }

        //extract the keys
        int inputIndex = keyLengthIndices[1];
        int keyIndex = 0;
        ArrayList<ArrayList<Byte>> buffer = new ArrayList<>();
        while(inputIndex < input.length && keyIndex < keyLengths.length){
            buffer.add(new ArrayList<Byte>());
            for (int i = 0; i < keyLengths[keyIndex]; inputIndex++, i++) {
                buffer.get(keyIndex).add(input[inputIndex]);
            }
            keyIndex++;
        }
        byte[][] keys = new byte[buffer.size()][];
        for (int i = 0; i < buffer.size(); i++) {
            keys[i] = new byte[buffer.get(i).size()];
            for (int j = 0; j < buffer.get(i).size(); j++) {
                keys[i][j] = buffer.get(i).get(j);
            }
        }
        return new KeyShareExtension(keys);
    }

    /*
    returns the start and end index of the keyLength fields in the format int[]{start, end}
     */
    private static int[] getKeyLengthIndices(byte[] input) {
        return new int[]{
                EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET,
                EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET + input[EXTENSION_KEY_SHARE_KEY_LENGTH_FIELDS_OFFSET - 1]*2
        };
    }

    public boolean equals(KeyShareExtension keyShareExtension){
        return
                java.util.Arrays.deepEquals(this.keys, keyShareExtension.keys) &&
                java.util.Arrays.deepEquals(this.keyLengths, keyShareExtension.keyLengths) &&
                java.util.Arrays.equals(this.byteRepresentation, keyShareExtension.byteRepresentation);

    }
}
