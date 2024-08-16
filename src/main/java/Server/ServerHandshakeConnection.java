package Server;

import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import messages.implementations.alerts.PQTLSAlertMessage;
import messages.messageConverter.ClientMessageConverter;
import messages.messageConverter.PQTLSMessageConverter;
import statemachines.server.ServerStateMachine;

import java.net.Socket;
/**
 * @author Robin Kroker
 */
public class ServerHandshakeConnection {
    private final Socket clientSocket;
    private final ServerStateMachine stateMachine;
    private final PQTLSServer server;
    private final boolean printHandShakeMessages;
    PQTLSMessageConverter messageConverter;

    public ServerHandshakeConnection(ServerStateMachine serverStateMachine, Socket clientSocket, PQTLSServer server, boolean printHandShakeMessages) {
        this.clientSocket = clientSocket;
        this.stateMachine = serverStateMachine;
        this.server = server;
        this.messageConverter = new ClientMessageConverter(this.stateMachine);
        this.printHandShakeMessages = printHandShakeMessages;
    }
    /**
     * Starts the Handshake, Servers doHandShake method must be called first
     * @throws Exception
     */
    public void doHandshake() throws Exception {
        synchronized(server){
            //wait for message
            PQTLSMessage recievedMessage = new NullMessage(), messageToSend = new NullMessage();
            while(!(recievedMessage instanceof PQTLSAlertMessage) && !stateMachine.finished()){
                messageConverter.setSharedSecret(stateMachine.getSharedSecret());
                recievedMessage = messageConverter.convertMessage(PQTLSMessageConverter.readMessageFromStream(clientSocket.getInputStream()));
                if(this.printHandShakeMessages){
                    System.out.println("Server received: ");
                    recievedMessage.printVerbose();
                }
                //send response
                messageToSend = stateMachine.step(recievedMessage);
                if(!(messageToSend instanceof NullMessage)){
                    if(this.printHandShakeMessages){
                        System.out.println("Server sends: ");
                        messageToSend.printVerbose();
                    }
                    clientSocket.getOutputStream().write(messageToSend.getBytes());
                }
                //set next message or step through states until the state returns the next message to send
                while(stateMachine.stepWithoutWaiting()){
                    messageToSend = stateMachine.step(new NullMessage());
                    if(!(messageToSend instanceof NullMessage)){
                        if(this.printHandShakeMessages){
                            System.out.println("Server sends: ");
                            messageToSend.printVerbose();
                        }
                        clientSocket.getOutputStream().write(messageToSend.getBytes());
                    }
                }
            }
        }
    }
    /**
     * Returns the statemachine used by this HandShakeConnection
     * @return ClientStateMachine
     */
    public ServerStateMachine getStateMachine() {
        return this.stateMachine;
    }
}
