package com.erhannis.tlschanneltest;

import com.erhannis.tlschanneltest.ContextFactory.Context;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
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

  public static void main(String[] args) throws IOException, GeneralSecurityException {

    // initialize the SSLContext, a configuration holder, reusable object
    Context ctx = ContextFactory.authenticatedContext("TLSv1.3", "node_2.ks", "node_2.ts");
    SSLContext sslContext = ctx.sslContext;
    //sslContext.createSSLEngine().setNeedClientAuth(true);
    
    // connect server socket channel normally
    try (ServerSocketChannel serverSocket = ServerSocketChannel.open()) {
      serverSocket.socket().bind(new InetSocketAddress(10000));

      // accept raw connections normally
      System.out.println("Waiting for connection...");
      try (SocketChannel rawChannel = serverSocket.accept()) {
        System.out.println("Connection inbound...");
        System.out.println("Local hash:");
        System.out.println(ctx.sha256Fingerprint);

        // create TlsChannel builder, combining the raw channel and the SSLEngine, using minimal
        // options
        ServerTlsChannel.Builder builder = ServerTlsChannel.newBuilder(rawChannel, sslContext)
                .withEngineFactory(sc -> {
                    SSLEngine se = sslContext.createSSLEngine();
                    se.setUseClientMode(false);
                    se.setNeedClientAuth(true);
                    return se;
                });

        // instantiate TlsChannel
        try (TlsChannel tlsChannel = builder.build()) {
          // write to stdout all data sent by the client
          ByteBuffer res = ByteBuffer.allocate(10000);
          while (tlsChannel.read(res) != -1) {
            res.flip();
            System.out.print(utf8.decode(res).toString());
            res.compact();
          }
        }
      }
    }
  }
}
