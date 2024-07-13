package statemachines.server;

import crypto.CryptographyModule;
import messages.PQTLSMessage;
import messages.extensions.PQTLSExtension;
import messages.extensions.implementations.SignatureAlgorithmsExtension;
import messages.implementations.CertificateMessage;
import messages.implementations.HelloMessage;
import messages.implementations.WrappedRecord;
import misc.Constants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import statemachines.State;
import statemachines.client.ClientStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Objects;

public class SendingCertificatesState extends State {
    ServerStateMachine stateMachine;
    byte[] clientSupportedSignatureAlgorithms;
    X509CertificateHolder[] certificatesToSend;
    @Override
    public void calculate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, CertificateException {
        determineClientSupportedSignatureAlgorithms();
        setCertificatesToSend();
        stateMachine.publicKeyUsedInCertificate =  new JcaX509CertificateConverter().getCertificate(certificatesToSend[0]).getPublicKey();
    }

    private void setCertificatesToSend(){
        ArrayList<X509CertificateHolder[]>[] splitCertificateChains = splitCertificateChainsByAlgorithm();
        certificatesToSend = splitCertificateChains[determineCertificateChainIndex(splitCertificateChains)].getFirst();
    }

    private int determineCertificateChainIndex(ArrayList<X509CertificateHolder[]>[] splitCertificateChains) {
        if(clientSupportedSignatureAlgorithms.length == 2 && stateMachine.supportedSignatureAlgorithms.length == 2 && !splitCertificateChains[2].isEmpty()){
            return 2;
        }else if(clientSupportedSignatureAlgorithms.length == 2 && stateMachine.supportedSignatureAlgorithms.length == 2){
            return 1;// Dilithium Certificates are much shorter
        }else if(serverAndClientSupportDilithium()){
            return 1;
        }else{
            return 0;
        }
    }

    private boolean serverAndClientSupportDilithium() {
        boolean serverSupportsDilithium = false;
        boolean clientSupportsDilithium = false;
        for(byte b : stateMachine.supportedSignatureAlgorithms){
            if(b == Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM){
                serverSupportsDilithium = true;
                break;
            }
        }
        for(byte b : clientSupportedSignatureAlgorithms){
            if(b == Constants.EXTENSION_SIGNATURE_ALGORITHMS_SUPPORTS_DILITHIUM){
                clientSupportsDilithium = true;
                break;
            }
        }
        return clientSupportsDilithium && serverSupportsDilithium;
    }

    private ArrayList<X509CertificateHolder[]>[] splitCertificateChainsByAlgorithm() {
        ArrayList<X509CertificateHolder[]> sphincsChains = new ArrayList<>();
        ArrayList<X509CertificateHolder[]> dilithiumChains = new ArrayList<>();
        ArrayList<X509CertificateHolder[]> bothAlgsChains = new ArrayList<>();
        for(X509CertificateHolder[] certificateChain : stateMachine.certificateChains){
            boolean usesSphincs = false;
            boolean usesDilithium = false;
            for(X509CertificateHolder certificate : certificateChain){
                if(Objects.equals(certificate.getSignatureAlgorithm().getAlgorithm().getId(), "1.3.6.1.4.1.22554.2.5")){
                    usesSphincs = true;
                }else{
                    usesDilithium = true;
                }
            }
            if(usesDilithium && usesSphincs){
                bothAlgsChains.add(certificateChain);
            }else if(usesSphincs){
                sphincsChains.add(certificateChain);
            }else{
                dilithiumChains.add(certificateChain);
            }
        }
        ArrayList<X509CertificateHolder[]>[] certificateChains = new ArrayList[3];
        certificateChains[0] = sphincsChains;
        certificateChains[1] = dilithiumChains;
        certificateChains[2] = bothAlgsChains;
        return certificateChains;
    }

    private void determineClientSupportedSignatureAlgorithms() {
        HelloMessage clientHello = (HelloMessage) stateMachine.messages.getFirst();
        PQTLSExtension[] extensions = clientHello.getExtensions();
        SignatureAlgorithmsExtension supportedSignatureAlgorithms = extractSignatureAlgorithmsExtension(extensions);
        clientSupportedSignatureAlgorithms = supportedSignatureAlgorithms.getSupportedSignatureAlgorithms();
    }

    private SignatureAlgorithmsExtension extractSignatureAlgorithmsExtension(PQTLSExtension[] extensions) {
        for(PQTLSExtension extension : extensions){
            if(extension.getIdentifier() == Constants.EXTENSION_IDENTIFIER_SIGNATURE_ALGORITHMS){
                return (SignatureAlgorithmsExtension) extension;
            }
        }
        throw new IllegalArgumentException("Extensions didnt contain SignatureAlgorithmsExtension!");
    }


    @Override
    public PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        return new WrappedRecord(
                new CertificateMessage(certificatesToSend),
                (byte) 0x0b,
                CryptographyModule.keys.byteArrToSymmetricKey(
                        stateMachine.sharedSecret.getServerHandShakeSecret(),
                        stateMachine.getPreferredSymmetricAlgorithm()
                ),
                stateMachine.sharedSecret.getServerHandShakeIVAndIncrement(),
                stateMachine.preferredCipherSuite
        );
    }
    //TODO
    @Override
    public State next() {
        return null;
    }

    @Override
    public void setPreviousMessage(PQTLSMessage message) {

    }

    @Override
    public void setStateMachine(ClientStateMachine stateMachine) {

    }

    @Override
    public void setStateMachine(ServerStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Override
    public boolean stepWithoutWaiting() {
        return true;
    }
}
