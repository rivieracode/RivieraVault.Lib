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
 * Shows the reference implementations for the PBKDF2Hasher.
 * 
 * @author Jean-Michel Tanguy
 */
public class PBKDF2HasherTest {
    
    /**
     * Constructs the test
     */
    public PBKDF2HasherTest() {
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
    public void testHash() throws Exception {
        String password = "MyStrongPassword";
        PBKDF2Hasher hasher = new PBKDF2Hasher();
        String sequence = hasher.hash(password);
        assertNotEquals(password, sequence);
        assertFalse( hasher.check("WrongPassword", sequence) );
        assertTrue( hasher.check(password, sequence) );
    }
    
    /**
     * @throws java.lang.Exception 
     */
    @Test
    public void testIterations() throws Exception {
        String password = "MyStrongPassword";
        PBKDF2Hasher hasher = new PBKDF2Hasher();
        String sequence = hasher.hash(password);
        // fooling the number of iterations
        sequence = "4095" + sequence.substring(4);
        assertFalse( hasher.check(password, sequence) );
    }

    
}
