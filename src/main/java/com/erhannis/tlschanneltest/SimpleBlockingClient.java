package com.erhannis.tlschanneltest;

import com.erhannis.tlschanneltest.ContextFactory.Context;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import tlschannel.ClientTlsChannel;
import tlschannel.TlsChannel;

// Derived from https://github.com/marianobarrios/tls-channel/tree/master/src/test/scala/tlschannel/example
/** Client example. Connects to a public TLS reporting service. */
public class SimpleBlockingClient {

  private static final Charset utf8 = StandardCharsets.UTF_8;

  public static final String domain = "localhost";
  public static final String message = "Client message to server\n";
  
  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, GeneralSecurityException {

    // initialize the SSLContext, a configuration holder, reusable object
    //SSLContext sslContext = SSLContext.getDefault();
    Context ctx = ContextFactory.authenticatedContext("TLSv1.3", "node_1.ks", "node_1.ts");
    SSLContext sslContext = ctx.sslContext;

    // connect raw socket channel normally
    try (SocketChannel rawChannel = SocketChannel.open()) {
      System.out.println("Local hash:");
      System.out.println(ctx.sha256Fingerprint);
      System.out.println("Connection outbound...");
      rawChannel.connect(new InetSocketAddress(domain, 10000));
      // Orrrr, if you're raring for a big bowl of unusually novel tedium....
      //ByteChannel rawChannel = new ConsoleChannel();

      // create TlsChannel builder, combining the raw channel and the SSLEngine, using minimal options
      SSLEngine engine = sslContext.createSSLEngine();
      engine.setUseClientMode(true);
      // Since we control both client and server, I'm restricting protocols to TLSv1.3 alone
      engine.setEnabledProtocols(new String[]{"TLSv1.3"});
      ClientTlsChannel.Builder builder = ClientTlsChannel.newBuilder(rawChannel, engine);
      /*
      // This is useful for seeing what cert(s) the client sent
      builder.withSessionInitCallback(ssls -> {
          ssls.getLocalCertificates();
      });
      */

      // instantiate TlsChannel
      try (TlsChannel tlsChannel = builder.build()) {
        tlsChannel.write(ByteBuffer.wrap(message.getBytes(StandardCharsets.US_ASCII)));
        
        // Server doesn't send a response, atm, fyi, but if it did, this should read it
        ByteBuffer res = ByteBuffer.allocate(10000);
        while (tlsChannel.read(res) != -1) {
          res.flip();
          System.out.print(utf8.decode(res).toString());
          res.compact();
        }
        res.flip();
        System.out.println(utf8.decode(res).toString());
      }
    }
  }
}
