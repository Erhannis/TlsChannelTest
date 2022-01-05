/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.erhannis.tlschanneltest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * Proof of concept - I have used this ByteChannel as the channel for the TlsChannels,
 * copy/pasting messages between the client and server's consoles, successfully
 * enacting a TLS connection.
 * 
 * (Just, if one asks for "RX N:", paste the corresponding "TX N:" from the other console.)
 * 
 * @author erhannis
 */
public class ConsoleChannel implements ByteChannel {
    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
    byte[] leftover = null;

    private int idrx = 0;
    
    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (leftover == null) {
            System.out.println("RX " + (idrx++) + ": ");
            String line = br.readLine();
            if (line == null) {
                return -1;
            }
            try {
                leftover = Hex.decodeHex(line);
            } catch (DecoderException ex) {
                Logger.getLogger(SimpleBlockingServer.class.getName()).log(Level.SEVERE, null, ex);
                leftover = new byte[0];
            }
        }

        int written = 0;
        if (dst.remaining() >= leftover.length) {
            dst.put(leftover);
            written = leftover.length;
            leftover = null;
        } else {
            written = dst.remaining();
            dst.put(leftover, 0, written);
            leftover = Arrays.copyOfRange(leftover, written, leftover.length);
        }
        return written;
    }

    @Override
    public boolean isOpen() {
        return true;
    }

    @Override
    public void close() throws IOException {
        System.err.println("CLOSE");
    }

    private int idtx = 0;
    
    @Override
    public int write(ByteBuffer src) throws IOException {
        byte[] bytes = new byte[src.remaining()];
        src.get(bytes);
        System.out.println("TX " + idtx + ": ");
        System.out.println(Hex.encodeHexString(bytes));
        System.out.println("");
        idtx++;
        return bytes.length;
    }
}
