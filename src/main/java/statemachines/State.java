package statemachines;

import messages.PQTLSMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

/**
 * @author Robin Kroker
 */
public interface State {
    /**
     * performs the calculations the state is responsible for
     * @throws Exception
     */
    void calculate() throws Exception;

    /**
     * Returns the message to send after the states calculate method is called
     * if there should be no message sent after calculate, it returns a null message
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws IOException
     */
    PQTLSMessage getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException;

    /**
     * returns the next state to step through
     * @return
     */
    State next();

    /**
     * sets the previous message for the state to use
     * @param message
     */
    void setPreviousMessage(PQTLSMessage message);

    /**
     * sets the statemachine that calls the calculate method
     * @param stateMachine
     */
    void setStateMachine(PQTLSStateMachine stateMachine);

    /**
     * if this method returns true, the user of the statemachine should call step until
     * this method returns false before waiting for an incoming message
     * @return
     */
    boolean stepWithoutWaitingForMessage();
}
