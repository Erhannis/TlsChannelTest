package com.erhannis.tlschanneltest;

import com.erhannis.tlschanneltest.ContextFactory.Context;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import tlschannel.ClientTlsChannel;
import tlschannel.TlsChannel;

/** Client example. Connects to a public TLS reporting service. */
public class SimpleBlockingClient {

  private static final Charset utf8 = StandardCharsets.UTF_8;

  public static final String domain = "localhost";//"www.howsmyssl.com";
  public static final String httpLine =
      "GET https://www.howsmyssl.com/a/check HTTP/1.0\nHost: www.howsmyssl.com\n\n";

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

      // create TlsChannel builder, combining the raw channel and the SSLEngine, using minimal
      // options
      ClientTlsChannel.Builder builder = ClientTlsChannel.newBuilder(rawChannel, sslContext);

      // instantiate TlsChannel
      try (TlsChannel tlsChannel = builder.build()) {

        // do HTTP interaction and print result
        tlsChannel.write(ByteBuffer.wrap(httpLine.getBytes(StandardCharsets.US_ASCII)));
        ByteBuffer res = ByteBuffer.allocate(10000);

        // being HTTP 1.0, the server will just close the connection at the end
        while (tlsChannel.read(res) != -1) {
          // empty
        }
        res.flip();
        System.out.println(utf8.decode(res).toString());
      }
    }
  }
}
