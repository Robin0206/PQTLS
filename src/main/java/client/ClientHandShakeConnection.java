package client;

import messages.messageConverter.PQTLSMessageConverter;
import messages.PQTLSMessage;
import messages.implementations.NullMessage;
import messages.implementations.alerts.PQTLSAlertMessage;
import messages.messageConverter.ServerMessageConverter;
import statemachines.client.ClientStateMachine;

import java.io.*;
import java.net.Socket;

public class ClientHandShakeConnection implements Closeable{
    private final ClientStateMachine statemachine;
    private final Socket socket;
    private final PQTLSClient client;
    private InputStreamReader streamReader;
    private BufferedReader reader;
    private PrintWriter writer;
    PQTLSMessageConverter messageConverter;

    public ClientHandShakeConnection(ClientStateMachine stateMachine, Socket socket, PQTLSClient pqtlsClient) throws IOException {
        this.statemachine = stateMachine;
        this.socket = socket;
        this.client = pqtlsClient;InputStreamReader streamReader = new InputStreamReader(socket.getInputStream());
        this.reader = new BufferedReader(streamReader);
        this.writer = new PrintWriter(socket.getOutputStream());
        this.messageConverter = new ServerMessageConverter(this.statemachine);
    }



    public ClientStateMachine getStateMachine() {
        return statemachine;
    }

    public void doHandshake() throws Exception {
        // The synchronized block avoids other methods being called on the client before the handshake is finished
        synchronized (client){
            PQTLSMessage messageToSend = new NullMessage();
            PQTLSMessage messageRecieved = new NullMessage();
            while(!(messageToSend instanceof PQTLSAlertMessage)){
                //send message
                messageToSend = statemachine.step(messageRecieved);
                socket.getOutputStream().write(messageToSend.getBytes());
                System.out.print("Client sent: ");
                messageToSend.printVerbose();
                //set next message or step through states until the state returns the next message to send
                while(statemachine.stepWithoutWaiting()){
                    messageToSend = statemachine.step(new NullMessage());
                }

                //wait for response
                byte[] messageByteBuffer;
                while((messageByteBuffer = socket.getInputStream().readAllBytes()) !=null){
                    messageRecieved = messageConverter.convertMessage(messageByteBuffer);
                    System.out.print("Client received: ");
                    messageRecieved.printVerbose();
                }
            }
        }
    }

    @Override
    public void close() throws IOException {
        writer.close();
        reader.close();
        streamReader.close();
    }
}
