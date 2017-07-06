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
import com.rivieracode.lib.vault.algo.AESCBC;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.List;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides methods to encrypt and decrypt phrases with a plain text password
 * using symmetric AES-128 algorithm.
 *
 * <p>
 * AES is a strong two way conversion. AES-128 is used as it is the
 * maximum authorized key length with standard JRE install. 
 * <p>
 * Security is enforced by mixing a salt and an IV (Initialization Vector) with the message:<br>
 * <ul>
 * <li>The salt is about being able to use the same password several times
 * without opening weaknesses to generate the secret key.
 * <li>The point of an IV is to tolerate the use of the same key to encrypt
 * several distinct messages.
 * </ul>

 *
 * @author Jean-Michel Tanguy
 */
public class AESVault {

    /**
     * Maximum authorized key length with standard JRE install
     */
    private final int BLOCK_SIZE = 128;
    /**
     * Default salt. Can be redefined by the constructor.
     */
    private byte[] salt = "AnySaltCanDoItFrom0To9".getBytes();
    /**
     * Default number of iterations, defined as acceptable. Can be redefined by
     * the constructor.
     */
    private int iteration = 100;

    /**
     * Constructs the AESVault with default parameters.
     */
    public AESVault() {
    }

    /**
     * Constructs the custom AESVault.
     *
     * @param salt the salt helps to protect the reuse of the password
     * @param iteration the number of iterations for the encryption
     */
    public AESVault(String salt, int iteration) {
        this.salt = salt.getBytes();
        this.iteration = iteration;
    }

    /**
     * Encrypts the message with the password.
     *
     * @param clearMessage the data from text or file to encrypt
     * @param password the plain text password for the encryption
     * @return the byte array containing the encrypted message
     * @throws Exception if any error, hiding reason for exception
     */
    public byte[] encrypt(byte[] clearMessage, String password) throws Exception {
        try {
            SecretKey symmetricKey = getKeyFromPassword(password, salt);
            // AES encryption
            byte[] chunk1Iv = AESCBC.generateIV(new SecureRandom());
            byte[] chunck2Message = AESCBC.encrypt(symmetricKey, chunk1Iv, clearMessage);
            // IV is provided with the encryption     
            return Util.concatChunks(chunk1Iv, chunck2Message);
        } catch (Exception ex) {
            // Hiding possible exception to prevent hints to external world
            //Logger.getLogger(AESVault.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception();
        }
    }

    /**
     * Decrypts the message with the password.
     *
     * @param encryptedMessage the message encrypted with AES
     * @param password the plain text password used to encrypt the message
     * @return the decrypted message
     * @throws Exception if any error, hiding reason for exception
     */
    public byte[] decrypt(byte[] encryptedMessage, String password) throws Exception {
        try {
            List<byte[]> chunckList = Util.splitChunks(encryptedMessage);
            if (chunckList.size() == 2) {
                byte[] chunk1Iv = chunckList.get(0);
                byte[] chunck2Message = chunckList.get(1);
                SecretKey symmetricKey = getKeyFromPassword(password, salt);
                byte[] plainMessage = AESCBC.decrypt(symmetricKey, chunk1Iv, chunck2Message);
                return plainMessage;
            }
        } catch (Exception ex) {
            // Hiding possible exception to prevent hints to external world
            //Logger.getLogger(AESVault.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception();
        }
        throw new Exception();
    }

    /**
     * Generates the AES symmetric key from the password.
     *
     * @param password The plain text password
     * @param salt the salt helps to protect the reuse of the password
     * @return the symmetric AES key
     * @throws Exception if any error, hiding reason for exception
     */
    private SecretKey getKeyFromPassword(String password, byte[] salt) throws Exception {
        try {
            PBEKeySpec passwordKey = new PBEKeySpec(password.toCharArray(), salt, iteration, BLOCK_SIZE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKey key = (PBEKey) factory.generateSecret(passwordKey);
            SecretKey secretKey = new SecretKeySpec(key.getEncoded(), "AES");
            return secretKey;
        } catch (Exception ex) {
            // Hiding possible exception to prevent hints to external world
            //Logger.getLogger(AESVault.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception();
        }
    }

}
