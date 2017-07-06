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

import java.security.NoSuchAlgorithmException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Shows the reference implementations for the SHA512Hasher.
 * 
 * @author Jean-Michel Tanguy
 */
public class SHA512HasherTest {
    
    /**
     * Constructs the test
     */
    public SHA512HasherTest() {
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
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testHash512() throws Exception {
        String password = "MyStrongPassword";
        SHA512Hasher hasher = new SHA512Hasher();
        String hash = hasher.hash(password);
        assertNotEquals(password, hash);
        assertFalse( hasher.check("WrongPassword", hash) );
        assertTrue( hasher.check(password, hash) );
    }

    
    
}
