package Server;

import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import messages.implementations.alerts.PQTLSAlertMessage;
import messages.messageConverter.ClientMessageConverter;
import messages.messageConverter.PQTLSMessageConverter;
import statemachines.server.ServerStateMachine;

import java.net.ServerSocket;
import java.net.Socket;

public class ServerHandshakeConnection {
    private final Socket clientSocket;
    private final ServerSocket serverSockert;
    private final ServerStateMachine stateMachine;
    private final PQTLSServer server;
    PQTLSMessageConverter messageConverter;

    public ServerHandshakeConnection(ServerStateMachine serverStateMachine, ServerSocket serverSocket, Socket clientSocket, PQTLSServer server) {
        this.clientSocket = clientSocket;
        this.serverSockert = serverSocket;
        this.stateMachine = serverStateMachine;
        this.server = server;
        this.messageConverter = new ClientMessageConverter(this.stateMachine);
    }

    public void doHandshake() throws Exception {
        synchronized(server){
            //wait for message
            byte[] messageByteBuffer;
            PQTLSMessage recievedMessage = new NullMessage(), messageToSend = new NullMessage();
            System.out.println("entering while loop");
            while(!(recievedMessage instanceof PQTLSAlertMessage) && !stateMachine.finished()){
                messageConverter.setSharedSecret(stateMachine.getSharedSecret());
                recievedMessage = messageConverter.convertMessage(PQTLSMessageConverter.readMessageFromStream(clientSocket.getInputStream()));
                System.out.println("Server received: ");
                recievedMessage.printVerbose();
                messageToSend = stateMachine.step(recievedMessage);
                if(!(messageToSend instanceof NullMessage)){
                    System.out.println("Server sends: ");
                    messageToSend.printVerbose();
                    clientSocket.getOutputStream().write(messageToSend.getBytes());
                }
                while(stateMachine.stepWithoutWaiting()){
                    messageToSend = stateMachine.step(new NullMessage());
                    if(!(messageToSend instanceof NullMessage)){
                        System.out.println("Server sends: ");
                        messageToSend.printVerbose();
                        clientSocket.getOutputStream().write(messageToSend.getBytes());
                    }
                }
            }
        }
    }

    public ServerStateMachine getStateMachine() {
        return this.stateMachine;
    }
}
