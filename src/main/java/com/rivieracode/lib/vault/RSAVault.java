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

import com.rivieracode.lib.vault.algo.AESCBC;
import com.rivieracode.lib.vault.algo.RSAECB;
import com.rivieracode.lib.vault.algo.Util;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Provides methods to exchange messages with RSA and AES-128 encryption .
 * 
 * <p>
 * The encrypted payload is composed of the following parts : 
 * <ul>
 * <li>Random IV used for the message encryption</li>
 * <li>AES-128 symmetric encryption of the message</li>
 * <li>RSA encryption of the symmetric key with recipient public key (recipient validation)</li>
 * <li>RSA encryption of the message hash with sender private key (sender validation)</li>
 * </ul>

 * @author Jean-Michel Tanguy
 */
public class RSAVault {

    /**
     * Standard length of encryption.
     * 192 and 256 bits may not be available without additional extension.
     */
    private final int BITS = 128; 

    /**
     * Initialization is costly.
     */
    private final KeyGenerator kgen = KeyGenerator.getInstance("AES");

    /**
     * Constructs the RSAVault
     * @throws NoSuchAlgorithmException if the Java version is old
     */
    public RSAVault() throws NoSuchAlgorithmException {
        kgen.init(BITS);
    }
    
    /**
     * Encrypts the message.
     * 
     * @param message the message to encrypt
     * @param senderPrivateKey  the private key of the sender to sign the message
     * @param recipientPublicKey the public key of the sender to encrypt the symmetric key
     * @return the encrypted message
     * @throws Exception exception is raised on any security problem
     */
    public byte[] encrypt(byte[] message, PrivateKey senderPrivateKey, PublicKey recipientPublicKey) throws Exception {
        // AES encryption
        SecretKey symmetricKey = kgen.generateKey();
        // Random salt
        byte[] chunk1Iv = AESCBC.generateIV(new SecureRandom());
        // AES symmetric  encryption of the message
        byte[] chunck2Message = AESCBC.encrypt(symmetricKey, chunk1Iv, message);
        // Signature (enforcing sender validation)
        byte[] chunck3Signature = Util.createSignature(chunck2Message,senderPrivateKey);
        // RSA encryption of the symmetric key
        byte[] chunck4Key = RSAECB.encrypt(symmetricKey, recipientPublicKey );
        // Payload creation      
        return Util.concatChunks(chunk1Iv, chunck2Message, chunck3Signature, chunck4Key);
    }
    
    /**
     * Decrypts the message.
     * 
     * @param encryptedMessage the encrypted message
     * @param senderPublicKey the sender public key to authenticate the sender
     * @param recipientPrivateKey the public key of the recipient who can decrypt the symmetric key
     * @return the plain message
     * @throws Exception exception is raised on any security problem
     */
    public byte[] decrypt(byte[] encryptedMessage, PublicKey senderPublicKey, PrivateKey recipientPrivateKey) throws Exception {
        List<byte[]> chunckList = Util.splitChunks(encryptedMessage);
        if (chunckList.size()>3) {
            byte[] chunk1Iv = chunckList.get(0);
            byte[] chunck2Message = chunckList.get(1);
            byte[] chunck3Signature = chunckList.get(2);
            byte[] chunck4Key = chunckList.get(3);
            // sender validation
            Util.verifySignature(chunck2Message, chunck3Signature, senderPublicKey);
            SecretKey symmetricKey = (SecretKey)RSAECB.decrypt(chunck4Key, recipientPrivateKey);
            byte[] plainMessage = AESCBC.decrypt(symmetricKey, chunk1Iv, chunck2Message);
            return plainMessage;
        }
        return null;
    }
    
    
  

}
