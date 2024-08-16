package messages.implementations.alerts;

/**
 *
 * @author Robin Kroker
 * RFC8446 Page 86
 * https://www.rfc-editor.org/rfc/rfc8446#section-6.2
 */
public enum AlertDescription {
    close_notify,
    unexpected_message,
    bad_record_mac,
    record_overflow,
    handshake_failure,
    bad_certificate,
    unsupported_certificate,
    certificate_revoked,
    certificate_expired,
    certificate_unknown,
    illegal_parameter,
    unknown_ca,
    access_denied,
    decode_error,
    decrypt_error,
    protocol_version,
    insufficient_security,
    internal_error,
    inappropriate_fallback,
    user_canceled,
    missing_extension,
    unsupported_extension,
    unrecognized_name,
    bad_certificate_status_response,
    unknown_psk_identity,
    certificate_required,
    no_application_protocol
}
