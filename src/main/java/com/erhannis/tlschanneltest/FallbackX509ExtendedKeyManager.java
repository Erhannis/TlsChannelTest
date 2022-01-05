/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.erhannis.tlschanneltest;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 *
 * @author erhannis
 */
public class FallbackX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private X509ExtendedKeyManager pkixKeyManager = null;
    
    public FallbackX509ExtendedKeyManager(KeyManagerFactory kmf) {
        // create a default JSSE X509TrustManager.
        KeyManager kms[] = kmf.getKeyManagers();

        /*
         * Iterate over the returned trustmanagers, look
         * for an instance of X509TrustManager. If found,
         * use that as our default trust manager.
         */
        for (int i = 0; i < kms.length; i++) {
            if (kms[i] instanceof X509ExtendedKeyManager) {
                pkixKeyManager = (X509ExtendedKeyManager) kms[i];
                return;
            }
        }
    }
    
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return pkixKeyManager.getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return pkixKeyManager.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return pkixKeyManager.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return pkixKeyManager.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return pkixKeyManager.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return pkixKeyManager.getPrivateKey(alias);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return pkixKeyManager.chooseEngineClientAlias(keyType, issuers, engine);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return pkixKeyManager.chooseEngineServerAlias(keyType, issuers, engine);
    }
}
