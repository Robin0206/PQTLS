package messages.extensions;

import messages.extensions.implementations.ECPointFormatsExtension;
import messages.extensions.implementations.KeyShareExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import messages.extensions.implementations.SupportedGroupsExtension;
import misc.ByteUtils;
import java.util.ArrayList;
import static misc.Constants.*;

/*
Class that's responsible for splitting and parsing extension bytes
 */

public class PQTLSExtensionFactory {
    public static PQTLSExtension generateFromBytes(byte[] input){
        return switch (input[1]) {// only the second byte gets used because the first is always 0x00
            case EXTENSION_IDENTIFIER_KEY_SHARE -> KeyShareExtension.fromBytes(input);
            case EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS -> SignatureAlgorithmsExtension.fromBytes(input);
            case EXTENSION_IDENTIFIER_EC_POINT_FORMATS -> ECPointFormatsExtension.fromBytes(input);
            case EXTENSION_IDENTIFIER_SUPPORTED_GROUPS -> SupportedGroupsExtension.fromBytes(input);
            default -> throw new IllegalArgumentException("Invalid Identifier");
        };
    }

    public static PQTLSExtension[] generateMultipleFromBytes(byte[] extensionBytes){
        byte[][] splitExtensionBytes = splitExtensionBytes(extensionBytes);
        PQTLSExtension[] result = new PQTLSExtension[splitExtensionBytes.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = generateFromBytes(splitExtensionBytes[i]);
        }
        return result;
    }

    private static byte[][] splitExtensionBytes(byte[] extensionBytes) {
        int index = 0;
        ArrayList<ArrayList<Byte>> splitExtensionBytesBuffer = new ArrayList<>();
        ArrayList<Byte> currentExtensionBuffer = new ArrayList<>();

        //split the extensions and put them into the splitExtensionBytesBuffer
        int followingBytes;
        while (index < extensionBytes.length) {

            //add the identifier and the length
            currentExtensionBuffer.add(extensionBytes[index]);
            currentExtensionBuffer.add(extensionBytes[index + 1]);
            currentExtensionBuffer.add(extensionBytes[index + 2]);
            currentExtensionBuffer.add(extensionBytes[index + 3]);
            //convert the length
            followingBytes = ByteUtils.byteArrToShort(new byte[]{
                    extensionBytes[index + 2],
                    extensionBytes[index + 3]
            });
            if(extensionBytes.length < index + followingBytes){
                System.out.println();
            }
            //update the index
            index += 4;
            if(index + followingBytes > extensionBytes.length){
                System.out.println(
                );
            }
            //add the bytes
            for (int i = 0; i < followingBytes; i++) {
                currentExtensionBuffer.add(extensionBytes[index]);
                index++;
            }
            splitExtensionBytesBuffer.add(new ArrayList<>(currentExtensionBuffer));
            currentExtensionBuffer.clear();
        }
        byte[][] result = new byte[splitExtensionBytesBuffer.size()][];

        //convert to byte arrays and add to result
        for (int i = 0; i < splitExtensionBytesBuffer.size(); i++) {
            byte[] currentExtension = new byte[splitExtensionBytesBuffer.get(i).size()];
            for (int j = 0; j < currentExtension.length; j++) {
                currentExtension[j] = splitExtensionBytesBuffer.get(i).get(j);
            }
            result[i] = currentExtension.clone();
        }
        return result;
    }
}
