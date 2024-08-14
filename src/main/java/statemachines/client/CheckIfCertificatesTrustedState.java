package statemachines.client;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.implementations.CertificateMessage;
import messages.implementations.NullMessage;
import messages.implementations.WrappedRecord;
import messages.implementations.alerts.AlertDescription;
import messages.implementations.alerts.AlertLevel;
import messages.implementations.alerts.PQTLSAlertMessage;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import statemachines.State;
import statemachines.server.ServerStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class CheckIfCertificatesTrustedState implements State {
    ClientStateMachine stateMachine;
    private WrappedRecord wrappedCertificateMessage;
    private CertificateMessage certificateMessage;
    private PQTLSMessage alertMessage;


    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        stateMachine.certificatesTrusted = checkIfCertificateChainsAreTrusted();
        //https://www.rfc-editor.org/rfc/rfc8446
        //page 88
        if (!stateMachine.certificatesTrusted) {
            alertMessage = new PQTLSAlertMessage(AlertLevel.fatal, AlertDescription.bad_certificate);
        }
    }

    private boolean checkIfCertificateChainsAreTrusted() throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException {
        for (X509CertificateHolder serverCertificate : certificateMessage.getCertificates()) {
            for (X509CertificateHolder clientCertificate : stateMachine.trustedCertificates) {
                if (clientCertificate.equals(serverCertificate)) {
                    stateMachine.certificateUsedByServer = serverCertificate;
                    stateMachine.sigAlgUsedByServer = new JcaX509CertificateConverter().getCertificate(serverCertificate).getSigAlgName();

                    return CryptographyModule.certificate.verifyCertificateChain(certificateMessage.getCertificates());
                }

            }
        }
        return false;
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        if (!(alertMessage == null)) {
            return new WrappedRecord(
                    alertMessage,
                    Constants.ALERT_MESSAGE,
                    CryptographyModule.keys.byteArrToSymmetricKey(
                            stateMachine.getSharedSecretHolder().getServerHandShakeSecret(),
                            stateMachine.symmetricAlgorithm
                    ),
                    stateMachine.getSharedSecretHolder().getServerHandShakeIVAndIncrement(),
                    stateMachine.getChosenCipherSuite()
            );
        }
        return new NullMessage();
    }

    @Override
    public State next() {
        return new SignatureVerifyState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.wrappedCertificateMessage = (WrappedRecord) message;
        this.certificateMessage = (CertificateMessage) (((WrappedRecord) message).getWrappedMessage());
    }

    @Override
    public void setStateMachine(ClientStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {

    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }

}
