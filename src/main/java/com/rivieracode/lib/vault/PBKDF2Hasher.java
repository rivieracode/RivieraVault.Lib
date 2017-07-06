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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Provides methods to securely hash and verify a password.
 * 
 * <p>
 * Hashing with PBKDF2-SHA256 (Password-Based Key Derivation Function 2) has the same 
 * purpose than the well known SHA algorithm but it is more appropriate, because of the constant increase
 * in processing power, by slowing down brute force attack.
 * <p>
 * Hashes are sequenced as iterations:salt:hash in a string for storage and later password validation.
 * <p>
 * Generated salt for each hash protects against predefined dictionary attacks and allows different sequences for same passwords.<br>
 * Choose the higher number of iterations possible the system can accept.
 * 
 * @author Jean-Michel Tanguy
 */
public class PBKDF2Hasher {
    
    private  final int SALT_BYTE_LENGTH;
    private  final int HASH_BYTE_LENGTH;
    private  final SecretKeyFactory SKF; 
    private  final int ITERATIONS;

    /**
     * Constructs the PBKDF2 with SHA256 hasher.
     * <p>
     * The number of iterations can be adapted for testing context or increased security. 
     * <p>
     * Note that the output sequence is the double in length of the salt and hash length plus iteration and separator characters.
     * 
     * @param iterations the maximum number of iterations possible the system can accept
     * @param saltByteLength the number of bytes for the salt (higher is better, typical 16)
     * @param hashByteLenth the number of bytes for the hash (higher is better, typical 32)
     * @throws java.security.NoSuchAlgorithmException if the Java version is old
     */
    public PBKDF2Hasher(int iterations, int saltByteLength, int hashByteLenth) throws NoSuchAlgorithmException  {
        SKF = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        this.ITERATIONS = iterations;
        this.SALT_BYTE_LENGTH = saltByteLength;
        this.HASH_BYTE_LENGTH = hashByteLenth; 
    }
    
    /**
     * Constructs the PBKDF2 with SHA256 hasher with acceptable security defaults.
     * 
     * <ul>
     * <li>Iterations : 4096</li>
     * <li>Salt : 16 bytes</li>
     * <li>Hash : 32 bytes</li>
     * </ul>
     * 
     * @throws java.security.NoSuchAlgorithmException if the Java version is old
     */
    public PBKDF2Hasher() throws NoSuchAlgorithmException  {
        SKF = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        this.ITERATIONS = 4096;
        this.SALT_BYTE_LENGTH = 16; // or 128 bits
        this.HASH_BYTE_LENGTH = 32; // or 256 bits
    }

    //--------------------------------------------------------------------------
    // Hashing
    //--------------------------------------------------------------------------
    
    /**
     * Hashes the text and returns a hash sequence as iterations:salt:hash.
     * 
     * <p>
     * The sequence is typically 102 characters long with defaults :
     * <ul>
     * <li>Iterations : 4 characters</li>
     * <li>Salt : 32 characters</li>
     * <li>Hash : 64 characters</li>
     * <li>Separators : 2 characters</li>
     * </ul>
     * 
     * @param text the text or password to hash
     * @return the hash sequence as iterations:salt:hash with a typical length of 102 characters
     * @throws NoSuchAlgorithmException if the Java version is old
     * @throws InvalidKeySpecException if the key cannot be created
     */
    public String hash(String text) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return hash(text, getSalt());
    }
    
    /**
     * Hashes a text with the salt and returns a hash sequence as iterations:salt:hash.
     * 
     * <p>
     * The sequence is typically 102 characters long with defaults :
     * <ul>
     * <li>Iterations : 4 characters</li>
     * <li>Salt : 32 characters</li>
     * <li>Hash : 64 characters</li>
     * <li>Separators : 2 characters</li>
     * </ul>
     * 
     * @param text the text or password to hash
     * @param salt the preferred Salt
     * @return the hash sequence as iterations:salt:hash with a typical length of 102 characters
     * @throws NoSuchAlgorithmException if the Java version is old
     * @throws InvalidKeySpecException if the key cannot be created
     */
    public String hash(String text, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException  {
        char[] chars = text.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(chars, salt, ITERATIONS, HASH_BYTE_LENGTH *8);
        byte[] hash = SKF.generateSecret(spec).getEncoded();
        return ITERATIONS + ":" + toHex(salt) + ":" + toHex(hash);
    }

    /**
     * Generates a random salt.
     * 
     * @return the salt random array
     * @throws NoSuchAlgorithmException if the Java version is old 
     */
    private byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        sr.nextBytes(salt);
        return salt;
    }

    /**
     * Converts bytes to string for storage. Common method.
     * 
     * @param array the byte array
     * @return the converted string.
     */
    private String toHex(byte[] array)  {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    //--------------------------------------------------------------------------
    // Validating
    //--------------------------------------------------------------------------
    
    /**
     * Validates a password versus a previously generated hash sequence.
     * 
     * @param text the password to validated
     * @param hashSequence the hash sequence as generated by the "hash" method 
     * @return true if passwords match, false otherwise
     * @throws InvalidKeySpecException if validation failed
     */
    public boolean check(String text, String hashSequence) throws InvalidKeySpecException  {
        String[] parts = hashSequence.split(":");
        int sequenceIterations = Integer.parseInt(parts[0]);
        byte[] salt = fromHex(parts[1]);
        byte[] hash = fromHex(parts[2]);
        PBEKeySpec spec = new PBEKeySpec(text.toCharArray(), salt, sequenceIterations, hash.length *8);
        byte[] textHash = SKF.generateSecret(spec).getEncoded();
        int diff = hash.length ^ textHash.length;
        for (int i = 0; i < hash.length && i < textHash.length; i++) {
            diff |= hash[i] ^ textHash[i];
        }
        return diff == 0;
    }

    /**
     * Reverses conversion from string to byte array.
     * 
     * @param hex the string of hex
     * @return the byte array
     */
    private byte[] fromHex(String hex)  {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

}
