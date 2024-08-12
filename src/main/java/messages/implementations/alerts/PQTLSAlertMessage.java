package messages.implementations.alerts;

import messages.PQTLSMessage;
import misc.ByteUtils;

import java.security.cert.CertificateException;
import java.util.ArrayList;

import static messages.implementations.alerts.AlertDescription.*;

public class PQTLSAlertMessage implements PQTLSMessage {
    private final AlertLevel alertLevel;
    private final AlertDescription alertDescription;
    public byte[] messageBytes;

    public PQTLSAlertMessage(byte[] messageBytes) {
        this.alertLevel = byteToAlertLevel(messageBytes[messageBytes.length-2]);
        this.alertDescription = byteToAlertDescription(messageBytes[messageBytes.length-1]);
        this.messageBytes = messageBytes;
    }

    public PQTLSAlertMessage(AlertLevel alertLevel, AlertDescription alertDescription) {
        this.alertLevel = alertLevel;
        this.alertDescription = alertDescription;
        this.setMessageBytes();
    }

    private void setMessageBytes() {
        ArrayList<Byte> buffer = new ArrayList<>();
        buffer.add((byte) 0x15);// content type
        buffer.add((byte) 0x03);
        buffer.add((byte) 0x04);// TLS-Version 1.3
        buffer.add((byte) 0x00);
        buffer.add((byte) 0x02);// num of following bytes
        buffer.add(alertLevelToByte(alertLevel));// Alert Level
        buffer.add(alertDescriptionToByte(alertDescription));// Alert description
        messageBytes = ByteUtils.toByteArray(buffer);
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public void printVerbose() throws CertificateException {
        System.out.println("=======================================Alert========================================");
        System.out.println("Alert level:       " + this.alertLevel.toString());
        System.out.println("Alert Description: " + this.alertDescription.toString());
    }

    @Override
    public boolean equals(PQTLSMessage message) {
        return false;
    }

    //RFC8446 Page 86
    //https://www.rfc-editor.org/rfc/rfc8446#section-6.2
    public byte alertDescriptionToByte(AlertDescription alertDescription) {
        return switch (alertDescription) {
            case close_notify -> (byte) 0;
            case unexpected_message -> (byte) 10;
            case bad_record_mac -> (byte) 20;
            case record_overflow -> (byte) 22;
            case handshake_failure -> (byte) 40;
            case bad_certificate -> (byte) 42;
            case unsupported_certificate -> (byte) 43;
            case certificate_revoked -> (byte) 44;
            case certificate_expired -> (byte) 45;
            case certificate_unknown -> (byte) 46;
            case illegal_parameter -> (byte) 47;
            case unknown_ca -> (byte) 48;
            case access_denied -> (byte) 49;
            case decode_error -> (byte) 50;
            case decrypt_error -> (byte) 51;
            case protocol_version -> (byte) 70;
            case insufficient_security -> (byte) 71;
            case internal_error -> (byte) 80;
            case inappropriate_fallback -> (byte) 86;
            case user_canceled -> (byte) 90;
            case missing_extension -> (byte) 109;
            case unsupported_extension -> (byte) 110;
            case unrecognized_name -> (byte) 112;
            case bad_certificate_status_response -> (byte) 113;
            case unknown_psk_identity -> (byte) 115;
            case certificate_required -> (byte) 116;
            case no_application_protocol -> (byte) 120;
        };
    }
    //RFC8446 Page 86
    //https://www.rfc-editor.org/rfc/rfc8446#section-6.2
    public AlertDescription byteToAlertDescription(byte input) {
        return switch (input) {
            case (byte) 0 -> close_notify;
            case (byte) 10 -> unexpected_message;
            case (byte) 20 -> bad_record_mac;
            case (byte) 22 -> record_overflow;
            case (byte) 40 -> handshake_failure;
            case (byte) 42 -> bad_certificate;
            case (byte) 43 -> unsupported_certificate;
            case (byte) 44 -> certificate_revoked;
            case (byte) 45 -> certificate_expired;
            case (byte) 46 -> certificate_unknown;
            case (byte) 47 -> illegal_parameter;
            case (byte) 48 -> unknown_ca;
            case (byte) 49 -> access_denied;
            case (byte) 50 -> decode_error;
            case (byte) 51 -> decrypt_error;
            case (byte) 70 -> protocol_version;
            case (byte) 71 -> insufficient_security;
            case (byte) 80 -> internal_error;
            case (byte) 86 -> inappropriate_fallback;
            case (byte) 90 -> user_canceled;
            case (byte) 109 -> missing_extension;
            case (byte) 110 -> unsupported_extension;
            case (byte) 112 -> unrecognized_name;
            case (byte) 113 -> bad_certificate_status_response;
            case (byte) 115 -> unknown_psk_identity;
            case (byte) 116 -> certificate_required;
            case (byte) 120 -> no_application_protocol;
            default -> throw new IllegalStateException("Unexpected value: " + input);
        };
    }

    //RFC8446 Page 86
    //https://www.rfc-editor.org/rfc/rfc8446#section-6.2
    private byte alertLevelToByte(AlertLevel alertLevel) {
        if (alertLevel == AlertLevel.warning) {
            return 1;
        } else {
            return 2;
        }
    }
    //RFC8446 Page 86
    //https://www.rfc-editor.org/rfc/rfc8446#section-6.2
    private AlertLevel byteToAlertLevel(byte input) {
        if (input == 1) {
            return AlertLevel.warning;
        } else {
            return AlertLevel.fatal;
        }
    }

}
