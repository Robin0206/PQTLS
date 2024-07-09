package misc;

import java.nio.ByteBuffer;

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
        return new byte[]{
                (byte) (input & 0xFF),
                (byte) ((input >> 8) & 0xFF),
                (byte) ((input >> 16) & 0xFF),
        };
    }
}
