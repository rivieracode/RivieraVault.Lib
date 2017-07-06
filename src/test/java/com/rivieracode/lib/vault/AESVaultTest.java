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

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Shows the reference implementations for the AESVault.
 * 
 * @author Jean-Michel Tanguy
 */
public class AESVaultTest {

    /**
     * Constructs the test
     */
    public AESVaultTest() {
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
    public void testAES() throws Exception {
        String myMessage = "My secret message";
        String myPassword = "MyStrongPassword";

        AESVault vault = new AESVault();
        byte[] mySecret = vault.encrypt(myMessage.getBytes(), myPassword);

        byte[] myTarget = vault.decrypt(mySecret, myPassword);
        String myClearMessage = new String(myTarget);

        assertEquals(myMessage, myClearMessage);
    }

    /**
     * @throws java.lang.Exception 
     */
    @Test
    public void testPassword() throws Exception {
        String myMessage = "My secret message";
        String myPassword = "MyStrongPassword";

        AESVault vault = new AESVault();
        byte[] mySecret = vault.encrypt(myMessage.getBytes(), myPassword);

        try {
            vault.decrypt(mySecret, "AnotherPassword");
            fail();
        } catch (Exception e) {
            // test is successful
        }
    }
}
