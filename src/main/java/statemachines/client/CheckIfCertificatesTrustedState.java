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
import statemachines.PQTLSStateMachine;
import statemachines.State;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Robin Kroker
 * This State expects a wrapped certificate message as an Argument to setPreviousMessage()
 * Responsible for checking if there is a trusted certificate in the servers certificate chains
 * If it cant find one the getMessage Method will return a Bad Certificate alert message
 * The next State is always the CertificateVerifyState
 */
public class CheckIfCertificatesTrustedState implements State {
    ClientStateMachine stateMachine;
    private CertificateMessage certificateMessage;
    private PQTLSMessage alertMessage;


    @Override
    public void calculate() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException, SignatureException {
        stateMachine.certificatesTrusted =
                checkIfCertificateChainsAreTrusted() && checkCertificatesDates();
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

    private boolean checkCertificatesDates() throws CertificateException {
        for (X509CertificateHolder serverCertificate : certificateMessage.getCertificates()){
            if(!CryptographyModule.certificate.verifyDate(CryptographyModule.certificate.holderToCertificate(serverCertificate))){
                return false;
            }
        }
        return true;
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
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
        this.certificateMessage = (CertificateMessage) (((WrappedRecord) message).getWrappedMessage());
    }

    @Override
    public void setStateMachine(PQTLSStateMachine stateMachine) {
        this.stateMachine = (ClientStateMachine) stateMachine;
    }

    @Override
    public boolean stepWithoutWaitingForMessage() {
        return false;
    }

}
