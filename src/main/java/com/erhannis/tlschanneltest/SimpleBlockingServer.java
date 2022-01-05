package com.erhannis.tlschanneltest;

import com.erhannis.tlschanneltest.ContextFactory.Context;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import tlschannel.ServerTlsChannel;
import tlschannel.TlsChannel;

// Derived from https://github.com/marianobarrios/tls-channel/tree/master/src/test/scala/tlschannel/example
/**
 * Server example. Accepts one connection and echos bytes sent by the client into standard output.
 *
 * <p>To test, use: <code>
 * openssl s_client -connect localhost:10000
 * </code>
 */
public class SimpleBlockingServer {

  private static final Charset utf8 = StandardCharsets.UTF_8;
  public static final String message = "Server message to client\n";

  public static void main(String[] args) throws IOException, GeneralSecurityException {

    // initialize the SSLContext, a configuration holder, reusable object
    Context ctx = ContextFactory.authenticatedContext("TLSv1.3", "node_2.ks", "node_2.ts");
    SSLContext sslContext = ctx.sslContext;
    
    // connect server socket channel normally
    try (ServerSocketChannel serverSocket = ServerSocketChannel.open()) {
      serverSocket.socket().bind(new InetSocketAddress(10000));

      // accept raw connections normally
      System.out.println("Waiting for connection...");
      try (SocketChannel rawChannel = serverSocket.accept()) {
        // OR you could do it by hand! ;P
        //ByteChannel rawChannel = new ConsoleChannel(); 
        
        System.out.println("Connection inbound...");
        System.out.println("Local hash:");
        System.out.println(ctx.sha256Fingerprint);

        // create TlsChannel builder, combining the raw channel and the SSLEngine, using minimal options
        ServerTlsChannel.Builder builder = ServerTlsChannel.newBuilder(rawChannel, sslContext)
                .withEngineFactory(sc -> {
                    SSLEngine se = sslContext.createSSLEngine();
                    se.setUseClientMode(false);
                    se.setNeedClientAuth(true);
                    // Since we control both client and server, I'm restricting protocols to TLSv1.3 alone
                    se.setEnabledProtocols(new String[] {"TLSv1.3"});
                    return se;
                });

        // instantiate TlsChannel
        try (TlsChannel tlsChannel = builder.build()) {
          // Careful; if the server and client both send at the same time without 
          //tlsChannel.write(ByteBuffer.wrap(message.getBytes(StandardCharsets.US_ASCII)));
          
          // write to stdout all data sent by the client
          ByteBuffer res = ByteBuffer.allocate(10000);
          while (tlsChannel.read(res) != -1) {
            res.flip();
            System.out.print(utf8.decode(res).toString());
            res.compact();
          }
          System.out.print(utf8.decode(res).toString());
          res.compact();
        }
      }
    }
  }
}
