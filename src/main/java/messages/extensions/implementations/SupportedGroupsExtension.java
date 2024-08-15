package messages.extensions.implementations;

import crypto.enums.CurveIdentifier;
import messages.extensions.PQTLSExtension;
import misc.ByteUtils;

import java.util.ArrayList;
import java.util.Hashtable;

import static crypto.enums.CurveIdentifier.*;
import static misc.Constants.EXTENSION_IDENTIFIER_SUPPORTED_GROUPS;

//Source: https://www.rfc-editor.org/rfc/rfc8446 section-4.2.7
//Extension used to negotiate the elliptic curve used in hybrid key exchange
/*
Structure:
||...Identifier...||...numOfFollowingBytes...||......curveIdentifiers......||
||----2-bytes-----||--------2-bytes----------||---2-bytes per identifier---||
 */

public class SupportedGroupsExtension implements PQTLSExtension {

    private static Hashtable<CurveIdentifier, byte[]> curveIdentifierToByteArr;
    private static Hashtable<Short, CurveIdentifier> shortToCurveIdentifier;// Uses short because you cant use byte arrays as keys
    private final CurveIdentifier[] supportedGroups;
    public byte[] byteRepresentation;


    public SupportedGroupsExtension(CurveIdentifier[] supportedGroups) {
        this.supportedGroups = supportedGroups;
        fillDictionaries();
        this.fillByteRepresentation();
    }

    private void fillByteRepresentation() {
        ArrayList<Byte> buffer = new ArrayList<>();
        buffer.add((byte) 0x00);
        buffer.add(EXTENSION_IDENTIFIER_SUPPORTED_GROUPS);
        byte[] numOfFollowingBytes = ByteUtils.shortToByteArr((short) (supportedGroups.length * 2));
        buffer.add(numOfFollowingBytes[0]);
        buffer.add(numOfFollowingBytes[1]);
        for(CurveIdentifier curveIdentifier : supportedGroups){
            buffer.add(curveIdentifierToByteArr.get(curveIdentifier)[0]);
            buffer.add(curveIdentifierToByteArr.get(curveIdentifier)[1]);
        }
        byteRepresentation = new byte[buffer.size()];
        for (int i = 0; i < byteRepresentation.length; i++) {
            byteRepresentation[i] = buffer.get(i);
        }
    }

    private static void fillDictionaries() {
        curveIdentifierToByteArr = new Hashtable<>();
        shortToCurveIdentifier = new Hashtable<>();

        curveIdentifierToByteArr.put(secp256r1, new byte[]{0x00, 0x17});
        curveIdentifierToByteArr.put(secp521r1, new byte[]{0x00, 0x19});
        curveIdentifierToByteArr.put(secp384r1, new byte[]{0x00, 0x18});

        shortToCurveIdentifier.put(ByteUtils.byteArrToShort(new byte[]{0x00, 0x17}), secp256r1);
        shortToCurveIdentifier.put(ByteUtils.byteArrToShort(new byte[]{0x00, 0x19}), secp521r1);
        shortToCurveIdentifier.put(ByteUtils.byteArrToShort(new byte[]{0x00, 0x18}), secp384r1);
    }

    @Override
    public byte[] getByteRepresentation() {
        return this.byteRepresentation;
    }

    @Override
    public void printVerbose() {
        System.out.println("=====Extension: Supported Groups");
        for (CurveIdentifier supportedGroup : supportedGroups) {
            System.out.println("\t"+supportedGroup.toString());
        }
    }

    @Override
    public byte getIdentifier() {
        return EXTENSION_IDENTIFIER_SUPPORTED_GROUPS;
    }

    public static PQTLSExtension fromBytes(byte[] input) {
        fillDictionaries();
        ArrayList<CurveIdentifier> buffer = new ArrayList<>();
        for (int i = 4; i < input.length; i+=2) {
            buffer.add(shortToCurveIdentifier.get(ByteUtils.byteArrToShort(new byte[]{input[i], input[i+1]})));
        }
        CurveIdentifier[] supportedGroups = new CurveIdentifier[buffer.size()];
        for (int i = 0; i < supportedGroups.length; i++) {
            supportedGroups[i] = buffer.get(i);
        }
        return new SupportedGroupsExtension(supportedGroups);
    }

    public CurveIdentifier[] getSupportedGroups() {
        return supportedGroups;
    }
}
