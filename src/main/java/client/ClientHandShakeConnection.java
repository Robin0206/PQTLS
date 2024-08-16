package client;



import messages.messageConverter.PQTLSMessageConverter;
import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import messages.messageConverter.ServerMessageConverter;
import statemachines.client.ClientStateMachine;
import java.net.Socket;

/**
 * @author Robin Kroker
 */
public class ClientHandShakeConnection {
    private final ClientStateMachine statemachine;
    private final Socket socket;
    private final PQTLSClient client;
    private final boolean printHandShakeMessages;
    private PQTLSMessageConverter messageConverter;

    /**
     * @param stateMachine
     * @param socket
     * @param pqtlsClient
     * @param printHandShakeMessages
     */
    public ClientHandShakeConnection(ClientStateMachine stateMachine, Socket socket, PQTLSClient pqtlsClient, boolean printHandShakeMessages){
        this.statemachine = stateMachine;
        this.socket = socket;
        this.client = pqtlsClient;
        this.messageConverter = new ServerMessageConverter(this.statemachine);
        this.printHandShakeMessages = printHandShakeMessages;
    }

    /**
     * Returns the statemachine used by this HandShakeConnection
     * @return ClientStateMachine
     */
    public ClientStateMachine getStateMachine() {
        return statemachine;
    }

    /**
     * Starts the Handshake, Servers doHandShake method must be called first
     * @throws Exception
     */
    public void doHandshake() throws Exception {
        // The synchronized block avoids other methods being called on the client before the handshake is finished
        synchronized (client) {
            PQTLSMessage messageToSend = new NullMessage();
            PQTLSMessage messageRecieved = new NullMessage();
            while (!statemachine.finished()) {
                //send message
                messageToSend = statemachine.step(messageRecieved);
                if(messageToSend == null){
                    break;
                }
                messageConverter.setSharedSecret(statemachine.getSharedSecret());
                if (!(messageToSend instanceof NullMessage)) {
                    socket.getOutputStream().write(messageToSend.getBytes());
                    if(printHandShakeMessages){
                        System.out.println("Client sent: ");
                        messageToSend.printVerbose();
                    }
                }
                //set next message or step through states until the state returns the next message to send
                while (statemachine.stepWithoutWaiting()) {
                    messageToSend = statemachine.step(new NullMessage());
                    if (!(messageToSend instanceof NullMessage)) {
                        socket.getOutputStream().write(messageToSend.getBytes());
                        if(printHandShakeMessages){
                            System.out.println("Client sent: ");
                            messageToSend.printVerbose();
                        }
                    }
                }

                //wait for response
                if(!statemachine.finished()){
                    messageRecieved = messageConverter.convertMessage(PQTLSMessageConverter.readMessageFromStream(socket.getInputStream()));
                    if(printHandShakeMessages){
                        System.out.println("Client received: ");
                        messageRecieved.printVerbose();
                    }
                }
            }
        }
    }
}
