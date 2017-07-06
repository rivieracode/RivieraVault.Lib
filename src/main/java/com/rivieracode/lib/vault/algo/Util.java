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

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

/**
 * Embeds helpers to manipulate keys and messages.
 *
 * @author Jean-Michel Tanguy
 */
public class Util {
    
    /**
     * Disable public instantiation
     */
    private Util() {
    }


    /**
     * Concatenates chunks of bytes. Each chunk is prefixed with its length coded on 4 bytes.
     * 2.1Go is the maximum length per chunk.
     *
     * @param list the byre arrays to concatenate
     * @return the concatenation in a single byte array
     */
    static public byte[] concatChunks(List<byte[]> list) {
        byte[] message = new byte[0];
        for (byte[] chunck : list) {
            message = merge(message, intToByteArray(chunck.length));
            message = merge(message, chunck);
        }
        return message;
    }

    /**
     * Concatenates chunks of bytes. Each chunk is prefixed with its length coded on 4 bytes.
     * 2.1Go is the maximum length per chunk.
     *
     * @param chunks the byte arrays to concatenate
     * @return the concatenation in a single byte array
     */
    static public byte[] concatChunks(byte[]... chunks) {
        byte[] message = new byte[0];
        for (byte[] chunck : chunks) {
            message = merge(message, intToByteArray(chunck.length));
            message = merge(message, chunck);
        }
        return message;
    }

    /**
     * Discovers and extracts each chunk from a concatenated byte array. 
     * This operation is the reverse of concatChunks.
     *
     * @param concatenation the concatenated byte array containing prefixed chunks
     * @return the list of extracted chunks
     */
    static public List<byte[]> splitChunks(byte[] concatenation) {
        List<byte[]> chunckList = new ArrayList<>();
        int index = 0;
        while (index < concatenation.length) {
            int sizeEnd = index + 4;
            int length = byteArrayToInt(Arrays.copyOfRange(concatenation, index, sizeEnd));
            int messageEnd = sizeEnd + length;
            byte[] b = Arrays.copyOfRange(concatenation, sizeEnd, messageEnd);
            chunckList.add(b);
            index = messageEnd;
        }
        return chunckList;
    }

    /**
     * Converts an {@code int} value to a 4 byte array.
     *
     * @param value the {@code int} number to convert
     * @return the 4 byte array
     */
    static public byte[] intToByteArray(int value) {
        byte[] data = new byte[4];
        // int -> byte[]   
        for (int i = 0; i < 4; ++i) {
            int shift = i << 3;  // i * 8        
            data[3 - i] = (byte) ((value & (0xff << shift)) >>> shift);
        }
        return data;
    }

    /**
     * Converts a 4 byte array to an {@code int} value.
     *
     * @param data the 4 byte array
     * @return the converted {@code int} value
     */
    static public int byteArrayToInt(byte[] data) {
        // byte[] -> int    
        int number = 0;
        for (int i = 0; i < 4; ++i) {
            number |= (data[3 - i] & 0xff) << (i << 3);
        }
        return number;
    }

    /**
     * Merges two byte arrays.
     *
     * @param a the primary array
     * @param b the following array
     * @return the simple concatenation of the arrays
     */
    static private byte[] merge(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /**
     * Calculates the signature with an SHA1 hash function signed by the RSA private key.
     *
     * @param message the message to sign
     * @param privateKey the private key certifying the authentication
     * @return the signature of the message
     * @throws java.security.NoSuchAlgorithmException if the version of Java is too old
     * @throws java.security.InvalidKeyException if the privateKey is invalid
     * @throws java.security.SignatureException if the signature could not be created
     */
    static public byte[] createSignature(byte[] message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateKey);
        sig.update(message);
        byte[] signature = sig.sign();
        return signature;
    }

    /**
     * Authenticates a message from the signature.
     *
     * @param message the message to authenticate
     * @param sentSignature the signature for the message
     * @param publicKey the public key pairing the private key used to create the signature
     * @throws java.security.NoSuchAlgorithmException if the version of Java is too old
     * @throws java.security.InvalidKeyException if the privateKey is invalid
     * @throws java.security.SignatureException if the signature could not be created
     * @throws Exception if signature is invalid
     */
    static public void verifySignature(byte[] message, byte[] sentSignature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, Exception  {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(message);  // Verify the signature    
         if (!sig.verify(sentSignature)) {
            throw new Exception("Invalid signature");
        }
    }

    /**
     * Generates a random phrase with readable characters.
     *
     * @param length the size of the random phrase
     * @return the random phrase
     */
    static public String generateRandomKey(int length) {
        String readableCharacters = "0123456789abcdefghjkmnopqrstwxyzABCDEFGHJKMNOPQRSTWXYZ";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            sb.append(readableCharacters.charAt(random.nextInt(readableCharacters.length())));
        }
        return sb.toString();
    }

    /**
     * Retrieves public and private keys from a key store.
     * 
     * @param keystore the key store with the private and public key
     * @param alias the alias of the key in the key store
     * @param aliasPassword the password for the alias in the key store
     * @return the KeyPair with private and public keys for the alias
     * @throws UnrecoverableKeyException if key is not valid
     * @throws KeyStoreException if key store is not valid
     * @throws NoSuchAlgorithmException if the Java version is old
     */
    public static KeyPair getKeyPair(KeyStore keystore, String alias, char[] aliasPassword) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        KeyPair keyPair = null;
        Key privateKey = keystore.getKey(alias, aliasPassword);
        if (privateKey instanceof PrivateKey) {
            Certificate cert = keystore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            keyPair = new KeyPair(publicKey, (PrivateKey) privateKey);
        }
        return keyPair;
    }

}
