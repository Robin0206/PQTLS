<h1>TLS-Library with quantum resistant cryptographic primitives<h1/>


<h4>primitives are provided by the Bouncy Castle library<h4/>
<p font-size="12">Usage in an Intellij project:<p/>

<p font-size="10">Add the pqtls.jar to your build path you also need to include the bouncy castle jars shown on the following picture:<p/>


<p font-size="10">You also need top add the following providers:<p/>

<p font-size="10">To make a server object you can use the class PQTLSServer.PQTLSServerBuilder. All methods shown in the picture below mut be called:<p/>

<p font-size="10">To make a client object you can use the class PQTLSClient.PQTLSClientBuilder. All methods shown in the picture below mut be called:<p/>
