package misc;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Robin Kroker
 */
public class ByteUtils {
    public static byte[] shortToByteArr(short input) {
        return new byte[]{(byte) (input / 128), (byte) (input % 128)};
    }

    public static short byteArrToShort(byte[] input) {
        return (short) ((input[0] * 128) + (input[1]));
    }

    public static byte[] longToByteArray(long input) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(input);
        return buffer.array();
    }

    public static byte[] intToByteArray3(int input) {
        BigInteger inputBigInteger = new BigInteger(String.valueOf(input));
        byte[] resultBuffer = inputBigInteger.toByteArray();
        byte [] result = new byte[3];
        if(resultBuffer.length > result.length){
            System.arraycopy(resultBuffer, 0, result, 0, result.length);
        }else{
            System.arraycopy(resultBuffer, 0, result, result.length - resultBuffer.length, resultBuffer.length);
        }
        return result;
    }
    public static byte[] flatten(byte[][] input){
        ArrayList<Byte> buffer = new ArrayList<>();
        for(byte[] arr : input){
            for(byte b : arr){
                buffer.add(b);
            }
        }
        byte[] result = new byte[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }
    public static byte[] flatten(ArrayList<byte[]> input){
        ArrayList<Byte> buffer = new ArrayList<>();
        for(byte[] arr : input){
            for(byte b : arr){
                buffer.add(b);
            }
        }
        byte[] result = new byte[buffer.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.get(i);
        }
        return result;
    }
    public static byte[] toByteArray(List<Byte> input){

        byte[] result = new byte[input.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = input.get(i);
        }
        return result;
    }

    public static byte[] increment(byte[] input) {
        BigInteger bigInteger = new BigInteger(input);
        bigInteger = bigInteger.add(BigInteger.ONE);
        return bigInteger.toByteArray();
    }

    public static int byteArrToInt(byte[] input) {
        return new BigInteger(input).intValue();
    }
}
