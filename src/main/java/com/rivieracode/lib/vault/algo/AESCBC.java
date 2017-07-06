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

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements the JRE features for AES encryption.
 * 
 * @author Jean-Michel Tanguy
 */
public class AESCBC {
    
    /**
     * Disable public instantiation.
     */
    private AESCBC() {
        
    }

    /**
     * The standard Initialization Vector (IV) length (128 bits).
     */
    private static final int IV_BIT_LENGTH = 128;

    /**
     * Generates a random 128 bit (16 byte) Initialization Vector(IV) for use in
     * AES encryption.
     *
     * @param randomGen the secure random generator to use
     * @return the random 128 bit IV, as 16 byte array
     */
    public static byte[] generateIV(SecureRandom randomGen) {
        byte[] bytes = new byte[IV_BIT_LENGTH / 8];
        randomGen.nextBytes(bytes);
        return bytes;
    }

    /**
     * Creates a new AES/CBC/PKCS5Padding cipher.
     *
     * @param secretKey the AES key
     * @param forEncryption if true creates an encryption cipher, else creates a decryption cipher
     * @param iv the initialization vector (IV)
     * @return the AES/CBC/PKCS5Padding cipher
     * @throws Exception if any error, hiding reason for exception
     */
    private static Cipher createAESCBCCipher(SecretKey secretKey, boolean forEncryption, byte[] iv) throws Exception {
        try {
            Cipher cipher;
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keyspec = new SecretKeySpec(secretKey.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            if (forEncryption) {
                cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivSpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, keyspec, ivSpec);
            }
            return cipher;
        } catch (Exception ex) { 
            // Hiding possible exception to prevent hints to external world
            //Logger.getLogger(AESCBC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception();
        }
    }

    /**
     * Encrypts the specified plain text using AES/CBC/PKCS5Padding.
     *
     * @param secretKey the AES key
     * @param iv the initialization vector (IV)
     * @param plainText the plain text
     * @return the cipher text
     * @throws Exception if any error, hiding reason for exception
     */
    public static byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] plainText) throws Exception {
        Cipher cipher = createAESCBCCipher(secretKey, true, iv);
        return cipher.doFinal(plainText);
    }

 

    /**
     * Decrypts the specified cipher text using AES/CBC/PKCS5Padding.
     *
     * @param secretKey the AES key
     * @param iv the initialization vector (IV)
     * @param cipherText the cipher text
     * @return the decrypted plain text
     * @throws Exception if any error, hiding reason for exception
     */
    public static byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] cipherText) throws Exception {
        Cipher cipher = createAESCBCCipher(secretKey, false, iv);
        return cipher.doFinal(cipherText);
    }

}
