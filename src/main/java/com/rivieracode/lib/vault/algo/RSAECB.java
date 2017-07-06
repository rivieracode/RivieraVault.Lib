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
package com.rivieracode.lib.vault.algo;

import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Implements the JRE features for RSA encryption.
 * 
 * @author Jean-Michel Tanguy
 */
public class RSAECB {

    /**
     * Disable public instantiation
     */
    private RSAECB() {

    }

    /**
     * Wraps a secret key using RSA.
     *
     * @param key the secret key to encrypt
     * @param publicKey the public key of the end user
     * @return the encrypted secret key
     * @throws Exception if any error, hiding reason for exception
     */
    public static byte[] encrypt(SecretKey key, PublicKey publicKey) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] wrappedKey = cipher.wrap(key);
            return wrappedKey;
        } catch (Exception ex) { 
            // Hiding possible exception to prevent hints to external world
            //Logger.getLogger(RSAECB.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception();
        }
    }

    /**
     * Unwraps a secret key from an RSA.
     *
     * @param wrappedKey the encrypted key
     * @param privateKey the private key of the end user
     * @return the secret key
     * @throws Exception if any error, hiding reason for exception
     */
    public static SecretKey decrypt(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            SecretKey symmetricKey = (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
            return symmetricKey;
        } catch (Exception ex) { 
            // Hiding possible exception to prevent hints to external world
            //Logger.getLogger(RSAECB.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception();
        }
    }

}
