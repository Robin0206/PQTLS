package misc;

public class ByteUtils {
    public static byte[] shortToByteArr(short input){
        return new byte[]{(byte)(input /128), (byte) (input%128)};
    }
    public static short byteArrToShort(byte[] input){
        return (short)((input[0] * 128)+(input[1]));
    }
}
