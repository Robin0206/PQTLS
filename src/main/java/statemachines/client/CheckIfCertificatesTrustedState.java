package statemachines.client;

import messages.PQTLSMessage;
import messages.implementations.CertificateMessage;
import messages.implementations.NullMessage;
import messages.implementations.WrappedRecord;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import statemachines.State;
import statemachines.server.ServerStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class CheckIfCertificatesTrustedState extends State {
    ClientStateMachine stateMachine;
    private WrappedRecord wrappedCertificateMessage;
    private CertificateMessage certificateMessage;


    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException {
        stateMachine.certificatesTrusted = checkIfCertificateChainsAreTrusted();
    }

    private boolean checkIfCertificateChainsAreTrusted() throws CertificateException {
        for(X509CertificateHolder serverCertificate : certificateMessage.getCertificates()) {
            for(X509CertificateHolder[] clientCertificateChain : stateMachine.trustedCertificates){
                for(X509CertificateHolder clientCertificate : clientCertificateChain){
                    if(clientCertificate.equals(serverCertificate)){
                        stateMachine.certificateUsedByServer = serverCertificate;
                        stateMachine.sigAlgUsedByServer = new JcaX509CertificateConverter().getCertificate(serverCertificate).getSigAlgName();
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return new NullMessage();
    }

    @Override
    public State next() {
        return new CertificateVerifyState();
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {
        this.wrappedCertificateMessage = (WrappedRecord) message;
        this.certificateMessage = (CertificateMessage)(((WrappedRecord)message).getWrappedMessage());
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
