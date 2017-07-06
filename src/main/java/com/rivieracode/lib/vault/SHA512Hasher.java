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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides methods to hash and verify a password using SHA-512.
 * 
 * <p>
 * Hashing is the standard one-way process to securely store and validate passwords.
 * SHA-512 is used for stronger straight hashing.
 * <p>
 * The hash function takes an arbitrary-sized password and output a fixed-length 128 character string.
 * <p>
 * PBKDF2 hashing should be preferred as it increases security for weak passwords.
 * 
 * @author Jean-Michel Tanguy
 */
public class SHA512Hasher {

    /**
     * SHA-512 algorithm, requires Java 8+
     */
    private final MessageDigest digest512;

    /**
     * Constructs the hasher.
     * 
     * @throws NoSuchAlgorithmException if Java version is old
     */
    public SHA512Hasher() throws NoSuchAlgorithmException {
            digest512 = MessageDigest.getInstance("SHA-512");
    }

    /**
     * Hashes a password.
     * 
     * @param text the password or text to hash
     * @return the hash as an hexadecimal string of 128 characters
     * @throws Exception if any error, hiding reason for exception
     */
    public String hash(String text) throws Exception {
        return SHA512Hasher.this.hash(digest512, text);
    }
    
    /**
     * Checks a password versus a previous hash.
     * 
     * @param text the password to validate
     * @param hash the hash of the reference password
     * @return true if passwords match, false otherwise
     * @throws Exception if any error, hiding reason for exception
     */
    public boolean check(String text, String hash) throws Exception {
        String textHash = SHA512Hasher.this.hash(digest512, text);
        return textHash.equals(hash);
    }

    /**
     * Hashes a text
     * @param digest
     * @param text
     * @return the hash as an hexadecimal string of 128 characters
     * @throws Exception if any error, hiding reason for exception
     */
    private String hash(MessageDigest digest, String text) throws Exception {
        try {
            byte[] hash = digest.digest(text.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();

            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]); //  0xFF for converting signed byte (-127 to 127) to unsigned int (0 to 255) before converting
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (UnsupportedEncodingException ex) {
            //Logger.getLogger(SHA512Hasher.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception();
        }
    }

}
