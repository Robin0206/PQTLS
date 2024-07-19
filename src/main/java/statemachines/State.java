package statemachines;

import messages.PQTLSMessage;
import statemachines.client.ClientStateMachine;
import statemachines.server.ServerStateMachine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public interface State {
    void calculate() throws Exception;
    PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException;
    State next();
    void setPreviousMessage(PQTLSMessage message);
    void setStateMachine(ClientStateMachine stateMachine);
    void setStateMachine(ServerStateMachine stateMachine);
    boolean stepWithoutWaitingForMessage();
}
