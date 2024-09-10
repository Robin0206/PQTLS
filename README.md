<h1>TLS-Library with quantum resistant cryptographic primitives<h1/>


<h4>primitives are provided by the Bouncy Castle library<h4/>
<p font-size="12">Usage in an Intellij project:<p/>
  
<p font-size="10">Add the pqtls.jar to your build path you also need to include the bouncy castle jars shown on the following picture:<p/>

<img width="200" alt="image" src="https://github.com/Robin0206/PQTLS/blob/main/providers.png"/>

<p font-size="10">You also need to add the following providers:<p/>

<img width="500" alt="image" src="https://github.com/Robin0206/PQTLS/blob/main/buildPath.png"/>
<p font-size="10">To make a server object you can use the class PQTLSServer.PQTLSServerBuilder. All methods shown in the picture below must be called:<p/>

<img width="800" alt="image" src="https://github.com/Robin0206/PQTLS/blob/main/server.png"/>
<p font-size="10">To make a client object you can use the class PQTLSClient.PQTLSClientBuilder. All methods shown in the picture below must be called:<p/>

<img width="800" alt="image" src="https://github.com/Robin0206/PQTLS/blob/main/client.png"/>

<p>-Calling the build method on the server starts the server</p>
<p>-Calling the build method on the client starts the handshake</p>
<p>You can use the method getProtocol on the client and the server. The return-value can be used like a regular object of class socket</p>
