/*
 * Copyright 2017 Jean-Michel Tanguy.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.rivieracode.lib.vault;

import com.rivieracode.lib.vault.algo.Util;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Shows the reference implementations for the RSAVault.
 * 
 * Test stores have been created using : 
 * keytool -genkeypair -keysize 2048 -keyalg RSA -alias user1 -keystore
 *
 * @author Jean-Michel Tanguy
 */
public class RSAVaultTest {

    /**
     * Constructs the test
     */
    public RSAVaultTest() {
    }

    /** */
    @BeforeClass
    public static void setUpClass() {
    }

    /** */
    @AfterClass
    public static void tearDownClass() {
    }

    /** */
    @Before
    public void setUp() {
    }

    /** */
    @After
    public void tearDown() {
    }

    /**
     * @throws java.lang.Exception
     */
    @Test
    public void testEncrypt() throws Exception {
        char[] storePassword = {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};
        KeyPair senderKeys = getKeyPair("/user1.store", "user1", storePassword);
        KeyPair recipientKeys = getKeyPair("/user2.store", "user2", storePassword);
        KeyPair agentKeys = getKeyPair("/user3.store", "user3", storePassword);

        String myMessage = "My very secret message";

        RSAVault vault = new RSAVault();
        byte[] mySecretMessage = vault.encrypt(myMessage.getBytes(), senderKeys.getPrivate(), recipientKeys.getPublic());
        byte[] myRecievedMessage = vault.decrypt(mySecretMessage, senderKeys.getPublic(), recipientKeys.getPrivate());
        assertEquals(myMessage, new String(myRecievedMessage));

        // any other key must fail
        try {
            vault.decrypt(mySecretMessage, senderKeys.getPublic(), agentKeys.getPrivate());
            fail();
        } catch (Exception e) {

        }
        try {
            vault.decrypt(mySecretMessage, agentKeys.getPublic(), recipientKeys.getPrivate());
            fail();
        } catch (Exception e) {

        }
    }

    /**
     * accessing embedded store
     *
     * @param store
     * @param alias
     * @param password
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     */
    private KeyPair getKeyPair(String store, String alias, char[] password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        InputStream is = RSAVaultTest.class.getResourceAsStream(store);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password);
        return Util.getKeyPair(keystore, alias, password);
    }

}
